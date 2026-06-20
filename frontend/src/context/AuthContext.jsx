import { createContext, useContext, useState, useEffect } from 'react'
import axios from 'axios'

const API = import.meta.env.VITE_API_URL || 'http://localhost:5000'
const AuthContext = createContext()

export function AuthProvider({ children }) {
  const [user, setUser]       = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const token = localStorage.getItem('token')
    if (token) {
      axios.get(`${API}/api/auth/me`, {
        headers: { Authorization: `Bearer ${token}` }
      }).then(r => {
        setUser(r.data)
        setLoading(false)
      }).catch(() => {
        localStorage.removeItem('token')
        setLoading(false)
      })
    } else {
      setLoading(false)
    }
  }, [])

  const login = async (email, password) => {
    const { data } = await axios.post(`${API}/api/auth/login`, { email, password })
    localStorage.setItem('token', data.token)
    setUser(data.user)
    return data
  }

  const register = async (name, email, password) => {
    const { data } = await axios.post(`${API}/api/auth/register`, { name, email, password })
    localStorage.setItem('token', data.token)
    setUser(data.user)
    return data
  }

  const logout = () => {
    localStorage.removeItem('token')
    setUser(null)
  }

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  return useContext(AuthContext)
}
