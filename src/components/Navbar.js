import { Link } from "react-router-dom";
import "../App.css"; // Ensure CSS is imported

const Navbar = () => {
  return (
    <>
    <div>
    <header>
          <h1>Phishing Detection Tool</h1> {/* Ensure this exists */}
        </header>
    </div>
    <nav className="navbar">
      <Link to="/email-phishing">Email Detection</Link>
      <Link to="/url-phishing">URL Detection</Link>
    </nav>
    </>
  );
};

export default Navbar;
