import './assets/styles.css';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import HomeView from './components/HomeView.jsx';

createRoot(document.getElementById('root')).render(
  <BrowserRouter>
    <Routes>
      <Route path="/" element={<HomeView />} />
      <Route path="/app/home" element={<HomeView />} />
      <Route path="*" element={<HomeView />} />
    </Routes>
  </BrowserRouter>
);
