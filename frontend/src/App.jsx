import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import useAuthStore from './store/authStore';

// Layout
import PageWrapper from './components/layout/PageWrapper';
import TourGuide from './components/layout/TourGuide';

// Pages
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import AssetInventory from './pages/AssetInventory';
import AssetDiscovery from './pages/AssetDiscovery';
import CBOM from './pages/CBOM';
import PQCPosture from './pages/PQCPosture';
import CyberRating from './pages/CyberRating';
import Reporting from './pages/Reporting';
import AIInsights from './pages/AIInsights';
import Admin from './pages/Admin';
import ScanDetails from './pages/ScanDetails';
import Blockchain from './pages/Blockchain';
import BankingTemplates from './pages/BankingTemplates';
import Compliance from './pages/Compliance';
import HeadersScan from './pages/HeadersScan';
import DNSScan from './pages/DNSScan';
import APIScan from './pages/APIScan';

const ProtectedRoute = ({ children }) => {
  const { isAuthenticated } = useAuthStore();
  
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  
  return <PageWrapper>{children}</PageWrapper>;
};

function App() {
  return (
    <BrowserRouter>
      {/* Tour lives at root level — only mounts once per session */}
      <TourGuide />
      <Routes>
        <Route path="/login" element={<Login />} />
        
        <Route path="/" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
        <Route path="/assets" element={<ProtectedRoute><AssetInventory /></ProtectedRoute>} />
        <Route path="/discovery" element={<ProtectedRoute><AssetDiscovery /></ProtectedRoute>} />
        <Route path="/cbom" element={<ProtectedRoute><CBOM /></ProtectedRoute>} />
        <Route path="/posture" element={<ProtectedRoute><PQCPosture /></ProtectedRoute>} />
        <Route path="/cyber-rating" element={<ProtectedRoute><CyberRating /></ProtectedRoute>} />
        <Route path="/reporting" element={<ProtectedRoute><Reporting /></ProtectedRoute>} />
        <Route path="/ai-insights" element={<ProtectedRoute><AIInsights /></ProtectedRoute>} />
        <Route path="/admin" element={<ProtectedRoute><Admin /></ProtectedRoute>} />
        <Route path="/scan/:id" element={<ProtectedRoute><ScanDetails /></ProtectedRoute>} />
        <Route path="/blockchain" element={<ProtectedRoute><Blockchain /></ProtectedRoute>} />
        <Route path="/banking-templates" element={<ProtectedRoute><BankingTemplates /></ProtectedRoute>} />
        <Route path="/compliance" element={<ProtectedRoute><Compliance /></ProtectedRoute>} />
        <Route path="/headers-scan" element={<ProtectedRoute><HeadersScan /></ProtectedRoute>} />
        <Route path="/dns-scan" element={<ProtectedRoute><DNSScan /></ProtectedRoute>} />
        <Route path="/api-scan" element={<ProtectedRoute><APIScan /></ProtectedRoute>} />
        
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;

