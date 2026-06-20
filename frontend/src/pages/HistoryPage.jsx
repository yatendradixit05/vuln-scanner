import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import axios from 'axios'

const API = import.meta.env.VITE_API_URL || 'http://localhost:5000'

const STATUS_STYLE = {
  completed: { background:'#dcfce7', color:'#16a34a' },
  running:   { background:'#dbeafe', color:'#1d4ed8' },
  failed:    { background:'#fee2e2', color:'#dc2626' },
  queued:    { background:'#f1f5f9', color:'#64748b' },
}

export default function HistoryPage() {
  const [scans, setScans]     = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    axios.get(`${API}/api/scans`)
      .then(r => { setScans(r.data); setLoading(false) })
      .catch(() => setLoading(false))
  }, [])

  const downloadReport = (scanId) => {
    const a   = document.createElement('a')
    a.href    = `${API}/api/scans/${scanId}/report`
    a.download = `vuln-report-${scanId}.pdf`
    a.click()
  }

  return (
    <div style={{ minHeight:'100vh', background:'#f8fafc',
      fontFamily:'system-ui, sans-serif' }}>

      <div style={{ background:'#1D3557', padding:'14px 32px', display:'flex',
        justifyContent:'space-between', alignItems:'center' }}>
        <span style={{ color:'#F1FAEE', fontWeight:800, fontSize:18 }}>
          Cyber <span style={{ color:'#E63946' }}>Sudarshan</span>
        </span>
        <Link to="/" style={{ color:'#F1FAEE', fontSize:13,
          textDecoration:'none', fontWeight:600 }}>
          New Scan
        </Link>
      </div>

      <div style={{ maxWidth:900, margin:'0 auto', padding:'32px 24px' }}>
        <div style={{ display:'flex', justifyContent:'space-between',
          alignItems:'center', marginBottom:24 }}>
          <div>
            <h2 style={{ margin:0, fontSize:22, color:'#0f172a' }}>Scan History</h2>
            <p style={{ margin:'4px 0 0', fontSize:13, color:'#64748b' }}>
              All previous scans
            </p>
          </div>
          <Link to="/" style={{ padding:'10px 20px', background:'#E63946',
            color:'#fff', borderRadius:8, textDecoration:'none',
            fontWeight:600, fontSize:14 }}>
            + New Scan
          </Link>
        </div>

        {loading && (
          <p style={{ textAlign:'center', color:'#94a3b8', marginTop:48 }}>
            Loading...
          </p>
        )}

        {!loading && scans.length === 0 && (
          <div style={{ textAlign:'center', marginTop:80 }}>
            <p style={{ color:'#94a3b8', fontSize:16 }}>No scans yet.</p>
            <Link to="/" style={{ color:'#E63946', fontWeight:600 }}>
              Start your first scan →
            </Link>
          </div>
        )}

        {scans.map(scan => {
          const date = new Date(scan.createdAt).toLocaleDateString('en-IN', {
            day:'numeric', month:'short', year:'numeric',
            hour:'2-digit', minute:'2-digit'
          })
          return (
            <div key={scan._id} style={{ background:'#fff', border:'1px solid #e2e8f0',
              borderRadius:12, padding:'20px 24px', marginBottom:12,
              display:'flex', justifyContent:'space-between',
              alignItems:'center', flexWrap:'wrap', gap:12 }}>
              <div style={{ flex:1, minWidth:200 }}>
                <p style={{ margin:'0 0 4px', fontWeight:600, fontSize:15,
                  color:'#0f172a' }}>{scan.targetUrl}</p>
                <p style={{ margin:0, fontSize:12, color:'#94a3b8' }}>{date}</p>
              </div>
              <div style={{ display:'flex', alignItems:'center', gap:10, flexWrap:'wrap' }}>
                <span style={{ ...STATUS_STYLE[scan.status] || STATUS_STYLE.queued,
                  padding:'3px 10px', borderRadius:20, fontSize:12, fontWeight:600 }}>
                  {scan.status}
                </span>
                <span style={{ fontSize:12, color:'#64748b' }}>{scan.progress}%</span>
                <Link to={`/scan/${scan._id}`}
                  style={{ padding:'7px 16px', background:'#1D3557', color:'#F1FAEE',
                    borderRadius:7, textDecoration:'none', fontSize:13, fontWeight:600 }}>
                  View
                </Link>
                {scan.status === 'completed' && (
                  <button onClick={() => downloadReport(scan._id)}
                    style={{ padding:'7px 16px', background:'#0D1B2A', color:'#F1FAEE',
                      border:'none', borderRadius:7, cursor:'pointer',
                      fontSize:13, fontWeight:600 }}>
                    ⬇ PDF
                  </button>
                )}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}