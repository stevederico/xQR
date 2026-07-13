import './assets/styles.css';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, Routes, Route } from 'react-router';
import HomeView from './components/HomeView.tsx';

const s = document.createElement('script');
s.defer = true;
s.src = 'https://aob.bixbyapps.com/script.js';
s.dataset.websiteId = '535354f8-732e-4630-b37a-b837ca1db1ba';
s.dataset.domains = 'xqr.bixbyapps.com';
document.head.appendChild(s);

// dottie analytics — env-loaded id (public repo: never hardcode the write_key)
if (import.meta.env.VITE_DOTTIE_SRC && import.meta.env.VITE_DOTTIE_ID) {
  const d = document.createElement('script');
  d.defer = true;
  d.src = import.meta.env.VITE_DOTTIE_SRC;
  d.dataset.websiteId = import.meta.env.VITE_DOTTIE_ID;
  d.dataset.domains = 'xqr.bixbyapps.com';
  document.head.appendChild(d);
}

const root = document.getElementById('root');
if (!root) {
  throw new Error('Root element not found');
}

createRoot(root).render(
  <BrowserRouter>
    <Routes>
      <Route path="/" element={<HomeView />} />
      <Route path="/app/home" element={<HomeView />} />
      <Route path="/:username" element={<HomeView />} />
      <Route path="*" element={<HomeView />} />
    </Routes>
  </BrowserRouter>
);
