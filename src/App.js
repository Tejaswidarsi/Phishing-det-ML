import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import Navbar from "./components/Navbar";
import EmailPhishing from "./components/EmailPhishing";
import URLPhishing from "./components/URLPhishing";
import "./App.css";

function App() {
  return (
    <Router>
      <div className="nav">
        <Navbar />
        </div>
        <div className="content">
        <Routes>
          <Route path="/email-phishing" element={<EmailPhishing />} />
          <Route path="/url-phishing" element={<URLPhishing />} />
          <Route path="/" element={<h2>Welcome to Phishing Detection Tool</h2>} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;
