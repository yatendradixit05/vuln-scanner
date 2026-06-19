import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

export default function RegisterPage() {
  const [name, setName]         = useState('')
  const [email, setEmail]       = useState('')
  const [password, setPassword] = useState('')
  const [error, setError]       = useState('')
  const [loading, setLoading]   = useState(false)
  const { register } = useAuth()
  const navigate     = useNavigate()

  const handleSubmit = async () => {
    if (!name || !email || !password) return setError('All fields required')
    if (password.length < 6) return setError('Password must be at least 6 characters')
    setError(''); setLoading(true)
    try {
      await register(name, email, password)
      navigate('/')
    } catch (err) {
      setError(err.response?.data?.error || 'Registration failed')
      setLoading(false)
    }
  }

  return (
    <div style={{ minHeight:'100vh', background:'#0D1B2A', display:'flex',
      alignItems:'center', justifyContent:'center', fontFamily:'system-ui, sans-serif' }}>
      <div style={{ background:'#fff', borderRadius:16, padding:'48px 40px',
        width:'100%', maxWidth:440, boxShadow:'0 20px 60px rgba(0,0,0,0.3)' }}>

        <div style={{ textAlign:'center', marginBottom:32 }}>
          <h1 style={{ margin:0, fontSize:26, color:'#0D1B2A', fontWeight:800 }}>
            Cyber <span style={{ color:'#E63946' }}>Sudarshan</span>
          </h1>
          <p style={{ margin:'6px 0 0', color:'#64748b', fontSize:14 }}>
            Create your account
          </p>
        </div>

        {error && (
          <div style={{ background:'#fef2f2', border:'1px solid #fecaca', borderRadius:8,
            padding:'10px 14px', marginBottom:16, color:'#dc2626', fontSize:13 }}>
            {error}
          </div>
        )}

        <label style={{ fontSize:13, fontWeight:600, color:'#334155',
          display:'block', marginBottom:6 }}>Full Name</label>
        <input type="text" value={name} onChange={e => setName(e.target.value)}
          placeholder="Yatendra Singh"
          style={{ width:'100%', padding:'11px 14px', fontSize:14, borderRadius:8,
            border:'1.5px solid #cbd5e1', outline:'none', boxSizing:'border-box',
            marginBottom:14 }} />

        <label style={{ fontSize:13, fontWeight:600, color:'#334155',
          display:'block', marginBottom:6 }}>Email</label>
        <input type="email" value={email} onChange={e => setEmail(e.target.value)}
          placeholder="you@example.com"
          style={{ width:'100%', padding:'11px 14px', fontSize:14, borderRadius:8,
            border:'1.5px solid #cbd5e1', outline:'none', boxSizing:'border-box',
            marginBottom:14 }} />

        <label style={{ fontSize:13, fontWeight:600, color:'#334155',
          display:'block', marginBottom:6 }}>Password</label>
        <input type="password" value={password} onChange={e => setPassword(e.target.value)}
          placeholder="Min 6 characters"
          onKeyDown={e => e.key === 'Enter' && handleSubmit()}
          style={{ width:'100%', padding:'11px 14px', fontSize:14, borderRadius:8,
            border:'1.5px solid #cbd5e1', outline:'none', boxSizing:'border-box',
            marginBottom:20 }} />

        <button onClick={handleSubmit} disabled={loading}
          style={{ width:'100%', padding:'13px', fontSize:15, fontWeight:700,
            background: loading ? '#94a3b8' : '#E63946', color:'#fff', border:'none',
            borderRadius:8, cursor: loading ? 'not-allowed' : 'pointer', marginBottom:16 }}>
          {loading ? 'Creating account...' : 'Create Account'}
        </button>

        <p style={{ margin:0, textAlign:'center', fontSize:13, color:'#64748b' }}>
          Already have an account?{' '}
          <Link to="/login" style={{ color:'#E63946', fontWeight:600,
            textDecoration:'none' }}>Sign In</Link>
        </p>
      </div>
    </div>
  )
}