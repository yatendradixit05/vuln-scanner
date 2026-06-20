import { useEffect, useState, useRef } from 'react'
import { useParams, Link } from 'react-router-dom'
import { io } from 'socket.io-client'
import axios from 'axios'

const API = import.meta.env.VITE_API_URL || 'http://localhost:5000'

const SEV_STYLE = {
  Critical: { background:'#E63946', color:'#fff' },
  High:     { background:'#F4831F', color:'#fff' },
  Medium:   { background:'#F4D03F', color:'#1a1a1a' },
  Low:      { background:'#2ECC71', color:'#fff' },
  Info:     { background:'#3498DB', color:'#fff' },
}

// ── Crawl Map ─────────────────────────────────
function CrawlMap({ nodes, edges, vulnUrls }) {
  const canvasRef = useRef(null)
  const animRef   = useRef(null)
  const posRef    = useRef({})

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    const W = canvas.width
    const H = canvas.height
    const cx = W / 2
    const cy = H / 2

    nodes.forEach((node, i) => {
      if (!posRef.current[node]) {
        if (i === 0) {
          posRef.current[node] = { x: cx, y: cy }
        } else {
          const angle  = (i / Math.max(nodes.length, 1)) * Math.PI * 2
          const radius = 80 + (i % 3) * 60 + Math.random() * 40
          posRef.current[node] = {
            x: Math.max(30, Math.min(W-30, cx + Math.cos(angle) * radius)),
            y: Math.max(30, Math.min(H-30, cy + Math.sin(angle) * radius)),
          }
        }
      }
    })

    let time = 0
    const draw = () => {
      ctx.clearRect(0, 0, W, H)
      ctx.fillStyle = '#0D1B2A'
      ctx.fillRect(0, 0, W, H)

      // Grid dots
      ctx.fillStyle = 'rgba(255,255,255,0.03)'
      for (let x = 0; x < W; x += 30)
        for (let y = 0; y < H; y += 30)
          ctx.fillRect(x, y, 1, 1)

      // Edges
      edges.forEach(([from, to]) => {
        const fp = posRef.current[from]
        const tp = posRef.current[to]
        if (!fp || !tp) return
        ctx.beginPath()
        ctx.moveTo(fp.x, fp.y)
        ctx.lineTo(tp.x, tp.y)
        ctx.strokeStyle = 'rgba(100,180,255,0.15)'
        ctx.lineWidth = 1
        ctx.stroke()
      })

      // Nodes
      nodes.forEach((node, i) => {
        const pos    = posRef.current[node]
        if (!pos) return
        const isVuln = vulnUrls.includes(node)
        const isRoot = i === 0
        const r      = isRoot ? 14 : 8

        if (isVuln) {
          const glow = Math.sin(time * 0.05) * 0.5 + 0.5
          ctx.beginPath()
          ctx.arc(pos.x, pos.y, r + 12, 0, Math.PI * 2)
          ctx.fillStyle = `rgba(230,57,70,${glow * 0.2})`
          ctx.fill()
          ctx.beginPath()
          ctx.arc(pos.x, pos.y, r + 6, 0, Math.PI * 2)
          ctx.fillStyle = `rgba(230,57,70,${glow * 0.4})`
          ctx.fill()
        }

        ctx.beginPath()
        ctx.arc(pos.x, pos.y, r, 0, Math.PI * 2)
        ctx.fillStyle   = isRoot ? '#E63946' : isVuln ? '#E63946' : '#1D3557'
        ctx.strokeStyle = isVuln ? '#E63946' : isRoot ? '#fff' : '#3498DB'
        ctx.lineWidth   = isRoot ? 2 : 1.5
        ctx.fill()
        ctx.stroke()

        const label = (node.replace(/https?:\/\/[^/]+/, '') || '/').substring(0, 22)
        ctx.fillStyle  = isVuln ? '#E63946' : 'rgba(255,255,255,0.6)'
        ctx.font       = `${isRoot ? 10 : 9}px monospace`
        ctx.textAlign  = 'center'
        ctx.fillText(label, pos.x, pos.y + r + 12)
      })

      time++
      animRef.current = requestAnimationFrame(draw)
    }

    draw()
    return () => cancelAnimationFrame(animRef.current)
  }, [nodes, edges, vulnUrls])

  return (
    <div style={{ background:'#0D1B2A', borderRadius:12,
      border:'1px solid #1D3557', overflow:'hidden', marginBottom:20 }}>
      <div style={{ padding:'12px 16px', borderBottom:'1px solid #1D3557',
        display:'flex', justifyContent:'space-between', alignItems:'center' }}>
        <span style={{ color:'#F1FAEE', fontWeight:700, fontSize:14 }}>
          Live Crawl Map
        </span>
        <div style={{ display:'flex', gap:16, fontSize:11 }}>
          <span style={{ color:'#3498DB' }}>● Crawled</span>
          <span style={{ color:'#E63946' }}>● Vulnerable</span>
        </div>
      </div>
      <canvas ref={canvasRef} width={860} height={300}
        style={{ width:'100%', height:300, display:'block' }}/>
    </div>
  )
}

// ── Cyber Score ───────────────────────────────
function CyberScore({ findings }) {
  const counts = { Critical:0, High:0, Medium:0, Low:0, Info:0 }
  findings.forEach(f => { counts[f.severity] = (counts[f.severity]||0) + 1 })

  const deductions =
    counts.Critical * 200 +
    counts.High     * 100 +
    counts.Medium   *  40 +
    counts.Low      *  10 +
    counts.Info     *   2

  const score = Math.max(0, Math.min(1000, 1000 - deductions))

  let grade, gradeColor, gradeDesc
  if      (score >= 900) { grade='A+'; gradeColor='#2ECC71'; gradeDesc='Excellent' }
  else if (score >= 800) { grade='A';  gradeColor='#27AE60'; gradeDesc='Very Good' }
  else if (score >= 700) { grade='B';  gradeColor='#F4D03F'; gradeDesc='Good' }
  else if (score >= 600) { grade='B-'; gradeColor='#F39C12'; gradeDesc='Fair' }
  else if (score >= 500) { grade='C';  gradeColor='#E67E22'; gradeDesc='Poor' }
  else if (score >= 300) { grade='D';  gradeColor='#E74C3C'; gradeDesc='Dangerous' }
  else                   { grade='F';  gradeColor='#C0392B'; gradeDesc='Critical Risk' }

  const pct = (score / 1000) * 100
  const circumference = 2 * Math.PI * 52

  return (
    <div style={{ background:'#fff', border:'1px solid #e2e8f0', borderRadius:12,
      padding:'24px', marginBottom:20 }}>
      <h3 style={{ margin:'0 0 20px', fontSize:16, color:'#0f172a' }}>
        Cyber Security Score
      </h3>
      <div style={{ display:'flex', alignItems:'center', gap:32, flexWrap:'wrap' }}>

        {/* Circle */}
        <div style={{ position:'relative', width:120, height:120, flexShrink:0 }}>
          <svg width="120" height="120" viewBox="0 0 120 120">
            <circle cx="60" cy="60" r="52"
              fill="none" stroke="#e2e8f0" strokeWidth="10"/>
            <circle cx="60" cy="60" r="52"
              fill="none" stroke={gradeColor} strokeWidth="10"
              strokeDasharray={circumference}
              strokeDashoffset={circumference * (1 - pct/100)}
              strokeLinecap="round"
              transform="rotate(-90 60 60)"
              style={{ transition:'stroke-dashoffset 1.2s ease' }}/>
          </svg>
          <div style={{ position:'absolute', inset:0, display:'flex',
            flexDirection:'column', alignItems:'center', justifyContent:'center' }}>
            <span style={{ fontSize:26, fontWeight:800,
              color:gradeColor, lineHeight:1 }}>{score}</span>
            <span style={{ fontSize:11, color:'#64748b' }}>/ 1000</span>
          </div>
        </div>

        {/* Grade */}
        <div style={{ flexShrink:0 }}>
          <div style={{ fontSize:60, fontWeight:900,
            color:gradeColor, lineHeight:1 }}>{grade}</div>
          <div style={{ fontSize:13, color:'#64748b', marginTop:4 }}>{gradeDesc}</div>
        </div>

        {/* Breakdown */}
        <div style={{ flex:1, minWidth:180 }}>
          {[
            ['Critical', counts.Critical, 200, '#E63946'],
            ['High',     counts.High,     100, '#F4831F'],
            ['Medium',   counts.Medium,    40, '#F4D03F'],
            ['Low',      counts.Low,       10, '#2ECC71'],
          ].map(([label, count, pts, color]) => (
            <div key={label} style={{ display:'flex', alignItems:'center',
              gap:8, marginBottom:8 }}>
              <span style={{ minWidth:58, fontSize:12,
                fontWeight:600, color }}>{label}</span>
              <div style={{ flex:1, height:6, background:'#f1f5f9',
                borderRadius:3, overflow:'hidden' }}>
                <div style={{
                  width:`${Math.min(100, count * pts / 2)}%`,
                  height:'100%', background:color, borderRadius:3,
                  transition:'width 0.8s ease'
                }}/>
              </div>
              <span style={{ fontSize:11, color:'#94a3b8',
                minWidth:70, textAlign:'right' }}>
                {count} × -{pts}pts
              </span>
            </div>
          ))}
          <div style={{ marginTop:6, fontSize:11, color:'#94a3b8' }}>
            Total deducted: {deductions} pts
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Severity Badge ────────────────────────────
function SeverityBadge({ sev }) {
  return (
    <span style={{ ...SEV_STYLE[sev] || SEV_STYLE.Info,
      padding:'2px 10px', borderRadius:12, fontSize:12, fontWeight:700 }}>
      {sev}
    </span>
  )
}

// ── Finding Card ──────────────────────────────
function FindingCard({ finding, index }) {
  const [open, setOpen] = useState(false)
  return (
    <div style={{ border:'1px solid #e2e8f0', borderRadius:10,
      marginBottom:10, overflow:'hidden' }}>
      <div onClick={() => setOpen(!open)}
        style={{ display:'flex', alignItems:'center', gap:12,
          padding:'12px 16px', cursor:'pointer',
          background: open ? '#f8fafc' : '#fff',
          borderBottom: open ? '1px solid #e2e8f0' : 'none' }}>
        <span style={{ color:'#94a3b8', fontSize:13, minWidth:24 }}>
          #{index}
        </span>
        <SeverityBadge sev={finding.severity} />
        <span style={{ fontWeight:600, fontSize:14, flex:1 }}>
          {finding.type}
        </span>
        <span style={{ color:'#64748b', fontSize:11 }}>
          CVSS {finding.cvss_score ?? '—'}
        </span>
        <span style={{ color:'#94a3b8', fontSize:18 }}>
          {open ? '▲' : '▼'}
        </span>
      </div>
      {open && (
        <div style={{ padding:'14px 16px', background:'#fff' }}>
          <p style={{ margin:'0 0 6px', fontSize:13, color:'#64748b' }}>
            {finding.url}
          </p>
          <p style={{ margin:'0 0 10px', fontSize:14 }}>
            {finding.description}
          </p>
          {finding.proof && (
            <div style={{ background:'#f1f5f9', borderRadius:6,
              padding:'8px 12px', fontFamily:'monospace', fontSize:12,
              marginBottom:10, color:'#334155' }}>
              {finding.proof}
            </div>
          )}
          {finding.fixSnippet && (
            <>
              <p style={{ margin:'0 0 4px', fontSize:12,
                fontWeight:600, color:'#16a34a' }}>
                Recommended Fix:
              </p>
              <div style={{ background:'#f0fdf4', border:'1px solid #bbf7d0',
                borderRadius:6, padding:'8px 12px', fontFamily:'monospace',
                fontSize:12, color:'#166534' }}>
                {finding.fixSnippet}
              </div>
            </>
          )}
          {finding.remediation_priority && (
            <p style={{ margin:'10px 0 0', fontSize:12, color:'#64748b' }}>
              Priority: <b>{finding.remediation_priority}</b>
            </p>
          )}
        </div>
      )}
    </div>
  )
}

// ── Main Page ─────────────────────────────────
export default function ResultsPage() {
  const { id } = useParams()
  const [scan, setScan]                 = useState(null)
  const [progress, setProgress]         = useState(0)
  const [phase, setPhase]               = useState('Initializing...')
  const [liveFindings, setLiveFindings] = useState([])
  const [status, setStatus]             = useState('queued')
  const [crawlNodes, setCrawlNodes]     = useState([])
  const [crawlEdges, setCrawlEdges]     = useState([])
  const [vulnUrls, setVulnUrls]         = useState([])
  const lastNodeRef = useRef(null)

  useEffect(() => {
    axios.get(`${API}/api/scans/${id}`).then(r => {
      setScan(r.data)
      setProgress(r.data.progress || 0)
      setPhase(r.data.phase || 'Queued')
      setStatus(r.data.status)
      setLiveFindings(r.data.findings || [])
    })

    const socket = io(API)
    socket.emit('join_scan', id)
    socket.on('scan_update', (msg) => {
      if (msg.progress !== undefined) setProgress(msg.progress)
      if (msg.phase)  setPhase(msg.phase)
      if (msg.status) setStatus(msg.status)

      // Update crawl map
      if (msg.phase && msg.phase.includes('Crawling')) {
        const match = msg.phase.match(/https?:\/\/[^\s]+/)
        if (match) {
          const newUrl = match[0]
          setCrawlNodes(prev => {
            if (prev.includes(newUrl)) return prev
            const updated = [...prev, newUrl]
            setCrawlEdges(e => lastNodeRef.current
              ? [...e, [lastNodeRef.current, newUrl]]
              : e)
            lastNodeRef.current = newUrl
            return updated
          })
        }
      }

      if (msg.finding) {
        setLiveFindings(prev => [msg.finding, ...prev])
        if (msg.finding.url) {
          setVulnUrls(prev => [...new Set([...prev, msg.finding.url])])
        }
      }
      if (msg.status === 'completed') {
        axios.get(`${API}/api/scans/${id}`).then(r => setScan(r.data))
      }
    })
    return () => socket.disconnect()
  }, [id])

  useEffect(() => {
    if (scan?.targetUrl && crawlNodes.length === 0) {
      setCrawlNodes([scan.targetUrl])
      lastNodeRef.current = scan.targetUrl
    }
  }, [scan])

  const countBySev = sev => liveFindings.filter(f => f.severity === sev).length
  const progressColor = progress < 33 ? '#3b82f6'
                      : progress < 66 ? '#f59e0b' : '#10b981'

  return (
    <div style={{ minHeight:'100vh', background:'#f8fafc',
      fontFamily:'system-ui, sans-serif' }}>

      {/* Navbar */}
      <div style={{ background:'#1D3557', padding:'14px 32px',
        display:'flex', justifyContent:'space-between', alignItems:'center' }}>
        <span style={{ color:'#F1FAEE', fontWeight:800, fontSize:18 }}>
          Cyber <span style={{ color:'#E63946' }}>Sudarshan</span>
        </span>
        <div style={{ display:'flex', gap:20 }}>
          <Link to="/" style={{ color:'#F1FAEE', fontSize:13,
            textDecoration:'none', fontWeight:600 }}>New Scan</Link>
          <Link to="/history" style={{ color:'#F1FAEE', fontSize:13,
            textDecoration:'none', fontWeight:600 }}>History</Link>
        </div>
      </div>

      <div style={{ maxWidth:900, margin:'0 auto', padding:'32px 24px' }}>

        {/* Header */}
        <div style={{ marginBottom:20 }}>
          <h2 style={{ margin:0, fontSize:22, color:'#0f172a' }}>
            Scan Results
          </h2>
          <p style={{ margin:'4px 0 0', fontSize:13, color:'#64748b' }}>
            {scan?.targetUrl || '—'}
          </p>
        </div>

        {/* Progress */}
        <div style={{ background:'#fff', border:'1px solid #e2e8f0',
          borderRadius:12, padding:'18px 20px', marginBottom:20 }}>
          <div style={{ display:'flex', justifyContent:'space-between',
            marginBottom:8 }}>
            <span style={{ fontSize:13, fontWeight:600,
              color:'#334155' }}>{phase}</span>
            <span style={{ fontSize:13, color:'#64748b' }}>{progress}%</span>
          </div>
          <div style={{ height:10, background:'#e2e8f0', borderRadius:8,
            overflow:'hidden' }}>
            <div style={{ width:`${progress}%`, height:'100%',
              background:progressColor, borderRadius:8,
              transition:'width 0.5s ease' }}/>
          </div>
          <div style={{ display:'flex', gap:8, marginTop:10, flexWrap:'wrap' }}>
            {['Critical','High','Medium','Low','Info'].map(s => (
              <div key={s} style={{ display:'flex', alignItems:'center',
                gap:4, fontSize:12 }}>
                <span style={{ ...SEV_STYLE[s], padding:'1px 8px',
                  borderRadius:10, fontWeight:700 }}>
                  {countBySev(s)}
                </span>
                <span style={{ color:'#94a3b8' }}>{s}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Crawl Map */}
        {crawlNodes.length > 1 && (
          <CrawlMap
            nodes={crawlNodes}
            edges={crawlEdges}
            vulnUrls={vulnUrls}
          />
        )}

        {/* Cyber Score */}
        {status === 'completed' && liveFindings.length > 0 && (
          <CyberScore findings={liveFindings} />
        )}

        {/* Download */}
        {status === 'completed' && (
          <a href={`${API}/api/scans/${id}/report`} download
            style={{ display:'inline-block', marginBottom:24,
              padding:'11px 28px', background:'#0D1B2A', color:'#F1FAEE',
              borderRadius:8, fontWeight:600, fontSize:14,
              textDecoration:'none' }}>
            ⬇ Download PDF Report
          </a>
        )}

        {/* Findings */}
        {liveFindings.length > 0 && (
          <>
            <h3 style={{ margin:'0 0 12px', fontSize:16, color:'#0f172a' }}>
              Findings ({liveFindings.length})
            </h3>
            {liveFindings.map((f, i) => (
              <FindingCard
                key={i}
                finding={f}
                index={liveFindings.length - i}
              />
            ))}
          </>
        )}

        {liveFindings.length === 0 && status !== 'completed' && (
          <p style={{ textAlign:'center', color:'#94a3b8', marginTop:48 }}>
            Scan in progress — findings will appear here in real time...
          </p>
        )}

        {liveFindings.length === 0 && status === 'completed' && (
          <p style={{ textAlign:'center', color:'#16a34a',
            marginTop:48, fontWeight:600 }}>
            No vulnerabilities found. Target appears clean.
          </p>
        )}
      </div>
    </div>
  )
}