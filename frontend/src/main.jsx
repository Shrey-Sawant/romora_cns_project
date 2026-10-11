import React, {useEffect, useState} from 'react'
import {createRoot} from 'react-dom/client'
import './styles.css'
import mountainDashboard from './assets/mountain-dashboard.jpg'
import mountainStego from './assets/mountain-stego.jpg'

const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'

async function responseError(response){
  let data
  try { data=await response.json() } catch { return `Backend request failed (${response.status}).` }
  const detail=data?.detail
  if(typeof detail==='string') return detail
  if(detail && typeof detail.error==='string') return detail.error
  return `Backend request failed (${response.status}).`
}

async function calculatePsnr(coverFile,stegoBlob){
  const [cover,stego]=await Promise.all([createImageBitmap(coverFile),createImageBitmap(stegoBlob)])
  try{
    if(cover.width!==stego.width||cover.height!==stego.height) throw new Error('Cover and stego image dimensions do not match.')
    const canvas=document.createElement('canvas')
    canvas.width=cover.width
    canvas.height=cover.height
    const context=canvas.getContext('2d',{willReadFrequently:true})
    if(!context) throw new Error('Image comparison is unavailable in this browser.')
    context.drawImage(cover,0,0)
    const coverPixels=context.getImageData(0,0,cover.width,cover.height).data
    context.drawImage(stego,0,0)
    const stegoPixels=context.getImageData(0,0,stego.width,stego.height).data
    let squaredError=0
    for(let i=0;i<coverPixels.length;i++){
      const difference=coverPixels[i]-stegoPixels[i]
      squaredError+=difference*difference
    }
    const meanSquaredError=squaredError/coverPixels.length
    return meanSquaredError===0?'∞':`${(20*Math.log10(255/Math.sqrt(meanSquaredError))).toFixed(2)} dB`
  }finally{
    cover.close()
    stego.close()
  }
}

async function flipPayloadBit(file){
  const bitmap=await createImageBitmap(file)
  try{
    const canvas=document.createElement('canvas')
    canvas.width=bitmap.width
    canvas.height=bitmap.height
    const context=canvas.getContext('2d',{willReadFrequently:true})
    if(!context) throw new Error('Image processing is unavailable in this browser.')
    context.drawImage(bitmap,0,0)
    const image=context.getImageData(0,0,bitmap.width,bitmap.height)
    const channelOffset=24*4
    if(image.data.length<=channelOffset) throw new Error('Image is too small to tamper with.')
    image.data[channelOffset]^=1
    context.putImageData(image,0,0)
    const blob=await new Promise((resolve,reject)=>canvas.toBlob(value=>value?resolve(value):reject(new Error('Could not encode the tampered PNG.')),'image/png'))
    return new File([blob],file.name,{type:'image/png'})
  }finally{
    bitmap.close()
  }
}

const Icon = ({name, size=18, stroke=2}) => {
  const paths = {
    shield: <><path d="M12 3 20 6v5c0 5-3.2 8.4-8 10-4.8-1.6-8-5-8-10V6l8-3Z"/><path d="m9 12 2 2 4-4"/></>,
    home: <><path d="m3 10 9-7 9 7"/><path d="M5 9v11h14V9"/><path d="M9 20v-6h6v6"/></>,
    key: <><circle cx="8" cy="15" r="4"/><path d="m11 12 8-8 3 3-2 2 2 2-3 3-2-2-3 3"/></>,
    send: <><path d="m22 2-7 20-4-9-9-4Z"/><path d="M22 2 11 13"/></>,
    receive: <><path d="M12 3v12"/><path d="m7 10 5 5 5-5"/><path d="M5 21h14"/></>,
    settings: <><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-2 2-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.6v.2h-2.8v-.2a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1-2-2 .1-.1a1.7 1.7 0 0 0 .3-1.9 1.7 1.7 0 0 0-1.6-1H3.7v-2.8h.2a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9l-.1-.1 2-2 .1.1a1.7 1.7 0 0 0 1.9.3 1.7 1.7 0 0 0 1-1.6v-.2h2.8v.2a1.7 1.7 0 0 0 1 1.6 1.7 1.7 0 0 0 1.9-.3l.1-.1 2 2-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.6 1h.2V14h-.2a1.7 1.7 0 0 0-1.6 1Z"/></>,
    lock: <><rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></>,
    image: <><rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="8" cy="9" r="1.3"/><path d="m4 17 5-5 4 4 3-3 5 5"/></>,
    check: <path d="m5 12 4 4L19 6"/>,
    x: <><path d="m6 6 12 12"/><path d="m18 6-12 12"/></>,
    copy: <><rect x="8" y="8" width="11" height="11" rx="2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/></>,
    upload: <><path d="M12 16V4"/><path d="m7 9 5-5 5 5"/><path d="M5 20h14"/></>,
    download: <><path d="M12 4v12"/><path d="m7 11 5 5 5-5"/><path d="M5 20h14"/></>,
    info: <><circle cx="12" cy="12" r="9"/><path d="M12 11v5"/><path d="M12 8h.01"/></>,
    arrow: <><path d="M5 12h14"/><path d="m13 6 6 6-6 6"/></>,
    refresh: <><path d="M20 11a8 8 0 0 0-14.9-3L3 11"/><path d="M3 5v6h6"/><path d="M4 13a8 8 0 0 0 14.9 3L21 13"/><path d="M21 19v-6h-6"/></>,
    paperclip: <path d="m20.5 12.5-8.7 8.7a6 6 0 0 1-8.5-8.5l9.3-9.3a4 4 0 0 1 5.7 5.7l-9.4 9.4a2 2 0 1 1-2.8-2.8l8.6-8.6"/>,
    gear: <><circle cx="12" cy="12" r="3"/><path d="M19 12a7 7 0 0 0-.2-1.7l2-1.2-2-3.4-2.1 1.2A7 7 0 0 0 15.3 6L15 3.6h-4L10.7 6a7 7 0 0 0-1.4.8L7.2 5.7l-2 3.4 2 1.2A7 7 0 0 0 7 12c0 .6.1 1.2.2 1.7l-2 1.2 2 3.4 2.1-1.2c.4.3.9.6 1.4.8l.3 2.4h4l.3-2.4c.5-.2 1-.5 1.4-.8l2.1 1.2 2-3.4-2-1.2c.1-.5.2-1.1.2-1.7Z"/></>,
  }
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={stroke} strokeLinecap="round" strokeLinejoin="round">{paths[name]}</svg>
}

function StatusDots(){
  return <div className="status-dots"><span>ECDH <b/></span><span>ECDSA <b/></span><span>RSA <b/></span><span>API <b/></span></div>
}

function Sidebar({page,setPage}){
  const items=[
    ['dashboard','Dashboard','home'],
    ['keys','Key Setup','key'],
    ['send','Send Secret','send'],
    ['receive','Receive Secret','receive'],
    ['settings','Settings','settings'],
  ]
  return <aside className="sidebar">
    <div className="brand"><span className="brand-icon"><Icon name="shield" size={20}/></span><span>ROMORA</span></div>
    <nav>
      {items.map(([id,label,icon])=><button key={id} className={page===id?'nav-item active':'nav-item'} onClick={()=>setPage(id)}><Icon name={icon}/><span>{label}</span></button>)}
    </nav>
    <div className="system-card"><span className="dot-check">✓</span><div><strong>System Ready</strong><small>All modules operational</small></div></div>
  </aside>
}

function Top(){return <div className="top"><StatusDots/></div>}

function SectionTitle({eyebrow,title,subtitle,icon}){return <div className="section-title"><div className="section-icon"><Icon name={icon} size={22}/></div><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1><p>{subtitle}</p></div></div>}

function Dashboard({setPage}){
  const tech=[
    ['key','ECDH','Key Exchange','blue'],['send','ECDSA','Digital Signature','green'],['lock','RSA-OAEP','Encrypted Message','red'],['image','LSB','Hidden in Image','purple']
  ]
  return <div className="page dashboard">
    <div className="hero">
      <div className="hero-copy"><div className="eyebrow">AUTHENTICATED ENCRYPTED IMAGE STEGANOGRAPHY</div><h1>Welcome to <em>ROMORA</em></h1><h2>Authenticated Encrypted<br/>Image Steganography</h2><p>Hide secret messages inside ordinary-looking images<br/>with end-to-end security, authentication, and privacy.</p><div className="hero-actions"><button className="primary" onClick={()=>setPage('send')}><Icon name="send"/> Send Secret <Icon name="arrow"/></button><button className="secondary" onClick={()=>setPage('receive')}><Icon name="receive"/> Receive Secret</button></div></div>
      <div className="hero-art"><div className="orb"/><img src={mountainDashboard}/><div className="hero-lock"><Icon name="lock" size={28}/></div></div>
    </div>
    <div className="tech-strip">{tech.map(([i,t,s,c])=><div className="tech-card" key={t}><div className={'tech-icon '+c}><Icon name={i}/></div><div><strong>{t}</strong><small>{s}</small></div></div>)}</div>
  </div>
}

function KeySetup({identity,onGenerate,error,isGenerating}){
  return <div className="page"><SectionTitle eyebrow="KEY MANAGEMENT" title="Key Setup" subtitle="Generate your cryptographic identity" icon="key"/>
    <div className="key-grid">
      <KeyCard type="ECDSA Identity" tag="P-256, SHA-256" icon="key" fp={identity?.ecdsa_fingerprint||'Not generated'} publicKey={identity?.ecdsa_public_key}/>
      <KeyCard type="RSA Identity" tag="2048-bit, OAEP" icon="lock" fp={identity?.rsa_fingerprint||'Not generated'} publicKey={identity?.rsa_public_key}/>
    </div>
    <button className="wide-primary" onClick={onGenerate} disabled={isGenerating}><Icon name="key"/> Generate Keys</button>
    {error&&<p role="alert" style={{color:'#c8453c',textAlign:'center',fontSize:10}}>{error}</p>}
    <div className="security-note"><Icon name="info"/> Private keys stay server-side and are never returned to the browser.</div>
  </div>
}
function KeyCard({type,tag,icon,fp,publicKey}){
  const [copyError,setCopyError]=useState('')
  const copy=async value=>{
    if(!value) return
    setCopyError('')
    try{await navigator.clipboard.writeText(value)}catch(err){setCopyError(err instanceof Error?`Clipboard failed: ${err.message}`:'Clipboard is unavailable.')}
  }
  return <div className="card key-card"><div className="key-head"><div className="round-icon"><Icon name={icon} size={24}/></div><div><h3>{type}</h3><span className="generated">● Status: {publicKey?'Generated':'Not generated'}</span></div><span className="tag">{tag}</span></div><label>Public Key Fingerprint (SHA-256)</label><div className="fingerprint">{fp}<button onClick={()=>copy(fp)} aria-label="Copy fingerprint"><Icon name="copy" size={16}/></button></div><button className="copy-btn" onClick={()=>copy(fp)}>Copy Fingerprint</button><button className="copy-btn" disabled={!publicKey} onClick={()=>copy(publicKey)}>Copy Public Key</button>{copyError&&<p role="alert" style={{color:'#c8453c',fontSize:9}}>{copyError}</p>}</div>
}

function Send({identity,draft,setDraft,onSend,error}){
  const {message,receiverKey,image}=draft
  const [localError,setLocalError]=useState('')
  const byteCount=new TextEncoder().encode(message).length
  const onFile=e=>{setDraft(previous=>({...previous,image:e.target.files?.[0]||null}));setLocalError('')}
  const submit=()=>{
    setLocalError('')
    if(!identity?.identity_id){setLocalError('Generate your identity keys before sending.');return}
    if(!receiverKey.trim()){setLocalError('Enter the receiver RSA public key.');return}
    if(!message){setLocalError('Enter a message to encrypt.');return}
    if(byteCount>190){setLocalError('Message exceeds the 190-byte UTF-8 limit.');return}
    if(!image){setLocalError('Choose a PNG cover image.');return}
    const form=new FormData()
    form.append('sender_identity_id',identity.identity_id)
    form.append('receiver_rsa_public_key',receiverKey)
    form.append('message',message)
    form.append('cover_image',image)
    onSend(form,image)
  }
  return <div className="page"><SectionTitle eyebrow="SECURE TRANSMISSION" title="Send Secret" subtitle="Securely hide an encrypted message inside an image." icon="send"/>
    <div className="steps-grid">
      <div className="card step-card"><div className="step-label">Step 1</div><h3>Receiver RSA Public Key</h3><textarea value={receiverKey} onChange={e=>setDraft(previous=>({...previous,receiverKey:e.target.value}))} placeholder="-----BEGIN PUBLIC KEY-----&#10;MIIBIjANBgkqhkiG9w0BAQEFAAO...&#10;-----END PUBLIC KEY-----"/><div className="valid">Paste a key generated on this backend deployment.</div></div>
      <div className="card step-card"><div className="step-label">Step 2</div><h3>Secret Message</h3><textarea value={message} onChange={e=>setDraft(previous=>({...previous,message:e.target.value}))} placeholder="Type your secret message here..."/><div className="counter">{byteCount} / 190 bytes <span><i style={{width:`${Math.min(100,byteCount/190*100)}%`}}/></span></div></div>
      <div className="card step-card"><div className="step-label">Step 3</div><h3>Choose Cover Image</h3><label className="dropzone"><Icon name="image" size={28}/><span>Drag and drop a PNG image here</span><small>or</small><button type="button">Browse Files</button><input type="file" accept="image/png" onChange={onFile}/></label><small className="hint">PNG · RGB/RGBA · Recommended 256×256 or larger</small></div>
    </div>
    {(localError||error)&&<p role="alert" style={{color:'#c8453c',textAlign:'center',fontSize:10}}>{localError||error}</p>}
    <button className="wide-primary" onClick={submit} disabled={!message||byteCount>190||!image}><Icon name="lock"/> Create Stego-Image</button>
  </div>
}

function Processing(){
  const items=['ECDH Session','ECDSA Authentication','RSA-OAEP Encryption','Payload Created','Embedding bits into image...']
  return <div className="page"><SectionTitle eyebrow="SECURE TRANSMISSION" title="Secure Processing" subtitle="Creating your stego-image using multiple layers of security..." icon="gear"/>
    <div className="processing card"><div className="timeline">{items.map((x,i)=><div className="timeline-row" key={x}><div className={'timeline-dot '+(i===4?'current':'done')}>{i===4?'5':'✓'}</div><div><strong>{x}</strong><small>{['Generating ephemeral keys...','Signing and verifying keys...','Encrypting message...','Preparing data for embedding...','Hiding encrypted payload using LSB...'][i]}</small></div></div>)}</div><div className="progress-ring"><div>78%</div></div></div>
    <button className="wide-primary" disabled>Processing</button>
  </div>
}

function Created({setPage,output,onCreateAnother}){
  return <div className="page"><div className="result-heading"><div className="success-circle">✓</div><div><h1>Stego Image Created</h1><p>Your message has been encrypted and hidden inside the image.</p></div></div>
    <div className="created-grid card"><div className="image-pair"><div><img src={output?.coverUrl||mountainStego}/><strong>Original Cover Image</strong></div><div><img src={output?.stegoUrl||mountainStego}/><strong>Stego Image</strong><small>(Encrypted + Hidden)</small></div><small>Image difference PSNR: {output?.psnr||'—'}</small></div><div className="result-side"><div className="check-list">{['ECDSA signature attached','RSA encrypted','LSB embedded','Ready for secure transmission'].map(x=><div key={x}>✓ <span>{x}</span></div>)}</div><button className="wide-primary" onClick={()=>{if(!output?.stegoUrl)return;const link=document.createElement('a');link.href=output.stegoUrl;link.download='romora_stego.png';link.click()}}><Icon name="download"/> Download Stego PNG</button><button className="secondary full" onClick={onCreateAnother}>Create Another</button></div></div>
    <button className="link-button" onClick={()=>setPage('receive')}>Go to Receive Secret →</button>
  </div>
}

function Receive({identity,setPage,onReceive,error}){
  const [image,setImage]=useState(null)
  const [senderKey,setSenderKey]=useState(identity?.ecdsa_public_key||'')
  const [localError,setLocalError]=useState('')
  const [busy,setBusy]=useState(false)
  const submit=async tamper=>{
    setLocalError('')
    if(!image){setLocalError('Choose a stego PNG image.');return}
    if(!senderKey.trim()){setLocalError('Enter the sender ECDSA public key.');return}
    setBusy(true)
    try{
      const uploaded=tamper?await flipPayloadBit(image):image
      const form=new FormData()
      form.append('sender_ecdsa_public_key',senderKey)
      form.append('stego_image',uploaded)
      await onReceive(form)
    }catch(err){setLocalError(err instanceof Error?err.message:'Could not prepare the PNG image.')}
    finally{setBusy(false)}
  }
  return <div className="page"><SectionTitle eyebrow="SECURE RECEPTION" title="Receive Secret" subtitle="Recover and verify a hidden message from an image." icon="receive"/>
    <div className="receive-grid">
      <div className="card step-card"><div className="step-label">Step 1</div><h3>Upload Stego Image</h3><label className="dropzone"><Icon name="image" size={28}/><span>Drag and drop a PNG image here</span><small>or</small><button type="button">Browse Files</button><input type="file" accept="image/png" onChange={e=>setImage(e.target.files?.[0]||null)}/></label><div className="valid">✓ PNG · RGB/RGBA · Recommended 256×256 or larger</div></div>
      <div className="card step-card"><div className="step-label">Step 2</div><h3>Sender ECDSA Public Key</h3><textarea value={senderKey} onChange={e=>setSenderKey(e.target.value)} placeholder="-----BEGIN PUBLIC KEY-----&#10;MIIBIjANBgkqhkiG9w0BAQ...&#10;-----END PUBLIC KEY-----"/><div className="valid">Use the sender identity public key.</div></div>
    </div>
    {(localError||error)&&<p role="alert" style={{color:'#c8453c',textAlign:'center',fontSize:10}}>{localError||error}</p>}
    <button className="wide-primary" onClick={()=>submit(false)} disabled={busy}><Icon name="key"/> Reveal Message</button>
    <button className="link-button" onClick={()=>submit(true)} disabled={busy}>Simulate Image Tampering (Flip 1 bit)</button>
    <button className="link-button" onClick={()=>setPage('failed')}>Demo verification failure</button>
  </div>
}

function Verification({failed,setPage,data}){
  if(failed) return <div className="page verification"><div className="verify-title failed"><div className="x-circle">×</div><div><h1>Verification Failed</h1><p>The message authenticity could not be verified.</p></div></div><div className="failure card"><div className="lock-badge"><Icon name="lock" size={28}/></div><div><h3>Plaintext Hidden</h3><p>The decrypted message will NOT be displayed because signature verification failed.</p></div></div><div className="failure-causes"><h3>Possible causes:</h3><ul><li>Image was modified</li><li>Sender key was substituted</li><li>Payload was corrupted</li><li>Invalid signature</li></ul></div><button className="secondary full" onClick={()=>setPage('receive')}><Icon name="refresh"/> Try Again</button></div>
  return <div className="page verification"><div className="verify-title"><div className="success-circle">✓</div><div><h1>Verification Successful</h1><p>Signature verified. Sender authenticity and message integrity confirmed.</p></div></div><div className="verified-grid"><div className="message-box card"><div className="lock-badge green"><Icon name="lock" size={25}/></div><div><label>Recovered Message</label><div className="message">{data?.plaintext}</div></div></div><div className="check-list card">{['RSA-OAEP decryption','ECDSA verification','Message integrity','Sender authenticity'].map(x=><div key={x}>✓ <span>{x}</span></div>)}</div></div><button className="link-button" onClick={()=>setPage('receive')}>Back to Receive Secret →</button></div>
}

function Settings(){return <div className="page"><SectionTitle eyebrow="APPLICATION" title="Settings" subtitle="ROMORA frontend configuration." icon="settings"/><div className="settings-card card"><div><strong>Backend API</strong><small>FastAPI endpoint used by ROMORA.</small></div><span>{API_BASE}</span><div><strong>Image policy</strong><small>Only lossless PNG files are accepted.</small></div><span className="pill">✓ PNG ONLY</span></div></div>}

function App(){
  const [page,setPage]=useState('dashboard')
  const [identity,setIdentity]=useState(()=>{try{return JSON.parse(sessionStorage.getItem('romora.identity')||'null')}catch{return null}})
  const [apiError,setApiError]=useState('')
  const [keyError,setKeyError]=useState('')
  const [keyGenerating,setKeyGenerating]=useState(false)
  const [verification,setVerification]=useState(null)
  const [output,setOutput]=useState(null)
  const [sendDraft,setSendDraft]=useState({message:'',receiverKey:'',image:null})
  const [sessionToken,setSessionToken]=useState(()=>sessionStorage.getItem('romora.sessionToken')||'')

  useEffect(()=>()=>{if(output?.coverUrl)URL.revokeObjectURL(output.coverUrl);if(output?.stegoUrl)URL.revokeObjectURL(output.stegoUrl)},[output])

  const generateKeys=async()=>{
    setKeyError('')
    setKeyGenerating(true)
    try{
      const response=await fetch(`${API_BASE}/keys/generate`,{method:'POST'})
      if(!response.ok) throw new Error(await responseError(response))
      const generated=await response.json()
      sessionStorage.setItem('romora.identity',JSON.stringify(generated))
      setIdentity(generated)
    }catch(err){setKeyError(err instanceof Error?err.message:'Could not generate keys.')}
    finally{setKeyGenerating(false)}
  }

  const sendSecret=async(form,coverFile)=>{
    setApiError('')
    setOutput(null)
    setPage('processing')
    try{
      const response=await fetch(`${API_BASE}/send`,{method:'POST',body:form})
      if(!response.ok) throw new Error(await responseError(response))
      const token=response.headers.get('X-Romora-Session-Token')
      if(!token) throw new Error('Backend did not return the image session token.')
      const stegoBlob=await response.blob()
      const psnr=await calculatePsnr(coverFile,stegoBlob)
      const created={coverUrl:URL.createObjectURL(coverFile),stegoUrl:URL.createObjectURL(stegoBlob),psnr}
      sessionStorage.setItem('romora.sessionToken',token)
      setSessionToken(token)
      setOutput(created)
      setPage('created')
    }catch(err){
      setApiError(err instanceof Error?err.message:'Could not create the stego image.')
      setPage('send')
    }
  }

  const receiveSecret=async(form)=>{
    setApiError('')
    setVerification(null)
    if(sessionToken) form.append('session_token',sessionToken)
    const response=await fetch(`${API_BASE}/receive`,{method:'POST',body:form})
    if(response.ok){
      const result=await response.json()
      setVerification(result)
      setPage(result.signature_verified===true?'verified':'failed')
      return
    }
    const errorText=await responseError(response)
    if(response.status===400||response.status===401){
      setVerification({ok:false,signature_verified:false,plaintext:null,error:errorText})
      setPage('failed')
      return
    }
    throw new Error(errorText)
  }

  const createAnother=()=>{
    setOutput(null)
    setSendDraft({message:'',receiverKey:'',image:null})
    setSessionToken('')
    sessionStorage.removeItem('romora.sessionToken')
    setPage('send')
  }

  const render=()=>({
    dashboard:<Dashboard setPage={setPage}/>,
    keys:<KeySetup identity={identity} onGenerate={generateKeys} error={keyError} isGenerating={keyGenerating}/>,
    send:<Send identity={identity} draft={sendDraft} setDraft={setSendDraft} onSend={sendSecret} error={apiError}/>,
    processing:<Processing/>,
    created:<Created setPage={setPage} output={output} onCreateAnother={createAnother}/>,
    receive:<Receive identity={identity} setPage={setPage} onReceive={receiveSecret} error={apiError}/>,
    verified:<Verification data={verification} setPage={setPage}/>,
    failed:<Verification failed data={verification} setPage={setPage}/>,
    settings:<Settings/>
  }[page] || <Dashboard setPage={setPage}/>)
  const navPage = ['processing','created','verified','failed'].includes(page) ? (page==='verified'||page==='failed'?'receive':'send') : page
  return <div className="app"><Sidebar page={navPage} setPage={setPage}/><main><Top/>{render()}</main></div>
}
createRoot(document.getElementById('root')).render(<App/>)
