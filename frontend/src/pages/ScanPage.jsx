import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import axios from 'axios'

const API = 'http://localhost:5000'

export default function ScanPage() {
  const [url, setUrl]         = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError]     = useState('')
  const navigate = useNavigate()

  const startScan = async () => {
    if (!url) return setError('Please enter a URL')
    setError('')
    setLoading(true)
    let targetUrl = url.trim()
    if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
      targetUrl = 'https://' + targetUrl
    }
    try {
      const { data } = await axios.post(`${API}/api/scans/start`, { targetUrl })
      navigate(`/scan/${data.scanId}`)
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to start scan')
      setLoading(false)
    }
  }

  return (
    <div style={{ minHeight:'100vh', background:'#0D1B2A',
      fontFamily:'system-ui, sans-serif' }}>

      <div style={{ background:'#1D3557', padding:'14px 32px', display:'flex',
        justifyContent:'space-between', alignItems:'center' }}>
        <span style={{ color:'#F1FAEE', fontWeight:800, fontSize:18 }}>
          Cyber <span style={{ color:'#E63946' }}>Sudarshan</span>
        </span>
        <Link to="/history" style={{ color:'#F1FAEE', fontSize:13,
          textDecoration:'none', fontWeight:600 }}>
          History
        </Link>
      </div>

      <div style={{ display:'flex', alignItems:'center', justifyContent:'center',
        padding:'60px 24px' }}>
        <div style={{ background:'#fff', borderRadius:16, padding:'48px 40px',
          width:'100%', maxWidth:520, boxShadow:'0 20px 60px rgba(0,0,0,0.3)' }}>

          <div style={{ textAlign:'center', marginBottom:32 }}>
            <h1 style={{ margin:0, fontSize:28, color:'#0D1B2A', fontWeight:800 }}>
              Cyber <span style={{ color:'#E63946' }}>Sudarshan</span>
            </h1>
            <p style={{ margin:'6px 0 0', color:'#64748b', fontSize:14 }}>
              Web Vulnerability Scanner — B.Tech Final Year Project
            </p>
          </div>

          <div style={{ background:'#f8fafc', borderRadius:10, padding:'14px 16px',
            marginBottom:24, border:'1px solid #e2e8f0' }}>
            <p style={{ margin:0, fontSize:13, color:'#475569', lineHeight:1.6 }}>
              Runs <b>5 automated phases</b>: Recon → Crawling → Attack → PoC → PDF Report.
              Tests for <b>OWASP Top 10</b> including SQLi, XSS, sensitive files, CORS and more.
            </p>
          </div>

          <label style={{ fontSize:13, fontWeight:600, color:'#334155',
            display:'block', marginBottom:6 }}>Target URL</label>
          <input type="text" placeholder="http://testphp.vulnweb.com"
            value={url} onChange={e => setUrl(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && startScan()}
            style={{ width:'100%', padding:'12px 14px', fontSize:15, borderRadius:8,
              border:'1.5px solid #cbd5e1', outline:'none', boxSizing:'border-box',
              marginBottom:8, fontFamily:'monospace' }} />

          {error && <p style={{ color:'#E63946', fontSize:13, margin:'0 0 8px' }}>{error}</p>}

          <button onClick={startScan} disabled={loading}
            style={{ width:'100%', padding:'13px', fontSize:15, fontWeight:700,
              background: loading ? '#94a3b8' : '#E63946', color:'#fff', border:'none',
              borderRadius:8, cursor: loading ? 'not-allowed' : 'pointer', marginBottom:16 }}>
            {loading ? 'Starting scan...' : 'Start Scan →'}
          </button>

          <p style={{ margin:0, fontSize:11, color:'#94a3b8', textAlign:'center' }}>
            Only scan targets you own or have explicit written permission to test.<br/>
            Safe targets: <code>testphp.vulnweb.com</code> · <code>demo.testfire.net</code>
          </p>
        </div>
      </div>
    </div>
  )
}