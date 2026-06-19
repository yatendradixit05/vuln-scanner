import { BrowserRouter, Routes, Route } from 'react-router-dom'
import ScanPage    from './pages/ScanPage'
import ResultsPage from './pages/ResultsPage'
import HistoryPage from './pages/HistoryPage'

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/"         element={<ScanPage />} />
        <Route path="/scan/:id" element={<ResultsPage />} />
        <Route path="/history"  element={<HistoryPage />} />
      </Routes>
    </BrowserRouter>
  )
}