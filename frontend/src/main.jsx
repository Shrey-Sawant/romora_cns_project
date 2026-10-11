import React, {useState} from 'react'
import {createRoot} from 'react-dom/client'
import './styles.css'
import mountainDashboard from './assets/mountain-dashboard.jpg'
import mountainStego from './assets/mountain-stego.jpg'

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

function KeySetup(){
  return <div className="page"><SectionTitle eyebrow="KEY MANAGEMENT" title="Key Setup" subtitle="Generate your cryptographic identity" icon="key"/>
    <div className="key-grid">
      <KeyCard type="ECDSA Identity" tag="P-256, SHA-256" icon="key" fp="A8:32:91:4C:2F:6D:96:71:E3:64:4A:8F:1C:2D:73:9E:6B:0A:4F:21:3C:8D:55:9E:12:AC:7B:4F"/>
      <KeyCard type="RSA Identity" tag="2048-bit, OAEP" icon="lock" fp="71:C4:29:8E:83:6F:11:9D:22:4C:7A:9B:EE:5D:1F:3A:68:9C:2E:44:7F:0D:16:58:9E:6C:3A:A8"/>
    </div>
    <button className="wide-primary"><Icon name="key"/> Generate Keys</button>
    <div className="security-note"><Icon name="info"/> Private keys are never displayed and are stored securely on your device/server.</div>
  </div>
}
function KeyCard({type,tag,icon,fp}){return <div className="card key-card"><div className="key-head"><div className="round-icon"><Icon name={icon} size={24}/></div><div><h3>{type}</h3><span className="generated">● Status: Generated</span></div><span className="tag">{tag}</span></div><label>Public Key Fingerprint (SHA-256)</label><div className="fingerprint">{fp}<button><Icon name="copy" size={16}/></button></div><button className="copy-btn">Copy Fingerprint</button></div>}

function Send({setPage}){
  const [message,setMessage]=useState('')
  const [image,setImage]=useState(null)
  const onFile=e=>{const f=e.target.files?.[0]; if(f) setImage(URL.createObjectURL(f))}
  return <div className="page"><SectionTitle eyebrow="SECURE TRANSMISSION" title="Send Secret" subtitle="Securely hide an encrypted message inside an image." icon="send"/>
    <div className="steps-grid">
      <div className="card step-card"><div className="step-label">Step 1</div><h3>Receiver RSA Public Key</h3><textarea placeholder="-----BEGIN PUBLIC KEY-----&#10;MIIBIjANBgkqhkiG9w0BAQEFAAO...&#10;-----END PUBLIC KEY-----"/><div className="valid">✓ Valid public key detected</div></div>
      <div className="card step-card"><div className="step-label">Step 2</div><h3>Secret Message</h3><textarea value={message} onChange={e=>setMessage(e.target.value)} placeholder="Type your secret message here..."/><div className="counter">{new TextEncoder().encode(message).length} / 190 bytes <span><i style={{width:`${Math.min(100,new TextEncoder().encode(message).length/190*100)}%`}}/></span></div></div>
      <div className="card step-card"><div className="step-label">Step 3</div><h3>Choose Cover Image</h3><label className="dropzone"><Icon name="image" size={28}/><span>Drag and drop a PNG image here</span><small>or</small><button type="button">Browse Files</button><input type="file" accept="image/png" onChange={onFile}/></label><small className="hint">PNG · RGB/RGBA · Recommended 256×256 or larger</small></div>
    </div>
    <button className="wide-primary" onClick={()=>setPage('processing')}><Icon name="lock"/> Create Stego-Image</button>
  </div>
}

function Processing({setPage}){
  const items=['ECDH Session','ECDSA Authentication','RSA-OAEP Encryption','Payload Created','Embedding bits into image...']
  return <div className="page"><SectionTitle eyebrow="SECURE TRANSMISSION" title="Secure Processing" subtitle="Creating your stego-image using multiple layers of security..." icon="gear"/>
    <div className="processing card"><div className="timeline">{items.map((x,i)=><div className="timeline-row" key={x}><div className={'timeline-dot '+(i===4?'current':'done')}>{i===4?'5':'✓'}</div><div><strong>{x}</strong><small>{['Generating ephemeral keys...','Signing and verifying keys...','Encrypting message...','Preparing data for embedding...','Hiding encrypted payload using LSB...'][i]}</small></div></div>)}</div><div className="progress-ring"><div>78%</div></div></div>
    <button className="wide-primary" onClick={()=>setPage('created')}>Continue Demo</button>
  </div>
}

function Created({setPage}){
  return <div className="page"><div className="result-heading"><div className="success-circle">✓</div><div><h1>Stego Image Created</h1><p>Your message has been encrypted and hidden inside the image.</p></div></div>
    <div className="created-grid card"><div className="image-pair"><div><img src={mountainStego}/><strong>Original Cover Image</strong></div><div><img src={mountainStego}/><strong>Stego Image</strong><small>(Encrypted + Hidden)</small></div></div><div className="result-side"><div className="check-list">{['ECDSA signature attached','RSA encrypted','LSB embedded','Ready for secure transmission'].map(x=><div key={x}>✓ <span>{x}</span></div>)}</div><button className="wide-primary"><Icon name="download"/> Download Stego PNG</button><button className="secondary full">Create Another</button></div></div>
    <button className="link-button" onClick={()=>setPage('receive')}>Go to Receive Secret →</button>
  </div>
}

function Receive({setPage}){
  return <div className="page"><SectionTitle eyebrow="SECURE RECEPTION" title="Receive Secret" subtitle="Recover and verify a hidden message from an image." icon="receive"/>
    <div className="receive-grid">
      <div className="card step-card"><div className="step-label">Step 1</div><h3>Upload Stego Image</h3><label className="dropzone"><Icon name="image" size={28}/><span>Drag and drop a PNG image here</span><small>or</small><button type="button">Browse Files</button><input type="file" accept="image/png"/></label><div className="valid">✓ PNG · RGB/RGBA · Recommended 256×256 or larger</div></div>
      <div className="card step-card"><div className="step-label">Step 2</div><h3>Sender ECDSA Public Key</h3><textarea placeholder="-----BEGIN PUBLIC KEY-----&#10;MIIBIjANBgkqhkiG9w0BAQ...&#10;-----END PUBLIC KEY-----"/><div className="valid">✓ Valid public key detected</div></div>
    </div>
    <button className="wide-primary" onClick={()=>setPage('verified')}><Icon name="key"/> Reveal Message</button>
    <button className="link-button" onClick={()=>setPage('failed')}>Demo verification failure</button>
  </div>
}

function Verification({failed,setPage}){
  if(failed) return <div className="page verification"><div className="verify-title failed"><div className="x-circle">×</div><div><h1>Verification Failed</h1><p>The message authenticity could not be verified.</p></div></div><div className="failure card"><div className="lock-badge"><Icon name="lock" size={28}/></div><div><h3>Plaintext Hidden</h3><p>The decrypted message will NOT be displayed because signature verification failed.</p></div></div><div className="failure-causes"><h3>Possible causes:</h3><ul><li>Image was modified</li><li>Sender key was substituted</li><li>Payload was corrupted</li><li>Invalid signature</li></ul></div><button className="secondary full" onClick={()=>setPage('receive')}><Icon name="refresh"/> Try Again</button></div>
  return <div className="page verification"><div className="verify-title"><div className="success-circle">✓</div><div><h1>Verification Successful</h1><p>Signature verified. Sender authenticity and message integrity confirmed.</p></div></div><div className="verified-grid"><div className="message-box card"><div className="lock-badge green"><Icon name="lock" size={25}/></div><div><label>Recovered Message</label><div className="message">Meet me at 5:30 PM.</div></div></div><div className="check-list card">{['RSA-OAEP decryption','ECDSA verification','Message integrity','Sender authenticity'].map(x=><div key={x}>✓ <span>{x}</span></div>)}</div></div><button className="link-button" onClick={()=>setPage('receive')}>Back to Receive Secret →</button></div>
}

function Settings(){return <div className="page"><SectionTitle eyebrow="APPLICATION" title="Settings" subtitle="ROMORA frontend configuration." icon="settings"/><div className="settings-card card"><div><strong>Backend API</strong><small>Set the FastAPI base URL when integration begins.</small></div><span>http://localhost:8000</span><div><strong>Image policy</strong><small>Only lossless PNG files are accepted.</small></div><span className="pill">✓ PNG ONLY</span></div></div>}

function App(){
  const [page,setPage]=useState('dashboard')
  const render=()=>({dashboard:<Dashboard setPage={setPage}/>,keys:<KeySetup/>,send:<Send setPage={setPage}/>,processing:<Processing setPage={setPage}/>,created:<Created setPage={setPage}/>,receive:<Receive setPage={setPage}/>,verified:<Verification setPage={setPage}/>,failed:<Verification failed setPage={setPage}/>,settings:<Settings/>}[page] || <Dashboard setPage={setPage}/>)
  const navPage = ['processing','created','verified','failed'].includes(page) ? (page==='verified'||page==='failed'?'receive':'send') : page
  return <div className="app"><Sidebar page={navPage} setPage={setPage}/><main><Top/>{render()}</main></div>
}
createRoot(document.getElementById('root')).render(<App/>)
