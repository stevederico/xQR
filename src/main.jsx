import './assets/styles.css';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import HomeView from './components/HomeView.jsx';

if (import.meta.env.VITE_ANALYTICS_ID && import.meta.env.VITE_ANALYTICS_SRC) {
  const s = document.createElement('script');
  s.defer = true;
  s.src = import.meta.env.VITE_ANALYTICS_SRC;
  s.dataset.websiteId = import.meta.env.VITE_ANALYTICS_ID;
  document.head.appendChild(s);
}

createRoot(document.getElementById('root')).render(
  <BrowserRouter>
    <Routes>
      <Route path="/" element={<HomeView />} />
      <Route path="/app/home" element={<HomeView />} />
      <Route path="*" element={<HomeView />} />
    </Routes>
  </BrowserRouter>
);
