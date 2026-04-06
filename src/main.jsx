import './assets/styles.css';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import HomeView from './components/HomeView.jsx';

const s = document.createElement('script');
s.defer = true;
s.src = 'https://aob.bixbyapps.com/script.js';
s.dataset.websiteId = '535354f8-732e-4630-b37a-b837ca1db1ba';
s.dataset.domains = 'xqr.bixbyapps.com';
document.head.appendChild(s);

createRoot(document.getElementById('root')).render(
  <BrowserRouter>
    <Routes>
      <Route path="/" element={<HomeView />} />
      <Route path="/app/home" element={<HomeView />} />
      <Route path="/:username" element={<HomeView />} />
      <Route path="*" element={<HomeView />} />
    </Routes>
  </BrowserRouter>
);
