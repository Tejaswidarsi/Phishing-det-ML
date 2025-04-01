import { useState } from "react";
import "../App.css";

const URLPhishing = () => {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [websiteAnalysis, setWebsiteAnalysis] = useState(null);

  const checkURL = async () => {
    setLoading(true);
    setError(null);
    setResult(null);
    setWebsiteAnalysis(null);

    try {
      const response = await fetch("http://127.0.0.1:5000/predict-url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ URL: url }),
      });

      const data = await response.json();
      console.log("Received Data:", data);

      if (data.error) {
        setError(data.error);
      } else {
        setWebsiteAnalysis(data);
        setResult(data.result || "Website Analysis Available");
      }
    } catch (error) {
      setError("Error connecting to the server.");
      console.error("Request Error:", error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="url-phishing">
      <h1>URL Phishing Detection</h1>
      <input
        type="text"
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        placeholder="Enter URL"
      />
      <button onClick={checkURL} disabled={loading}>
        {loading ? "Checking..." : "Check URL"}
      </button>

      {error && <p style={{ color: "red" }}>{error}</p>}
      {result && <p><strong>Result:</strong> {result}</p>}

      
      {websiteAnalysis && (
                <div className="analysis-box">
                    <h3>Website Analysis:</h3>
                    <p><strong>Analysis:</strong> {websiteAnalysis.website_analysis}</p>
                    {websiteAnalysis.result === "Phishing" ? (
                        <p className="warning"><strong>Warning:</strong> This URL is flagged as potentially dangerous. Avoid visiting it.</p>
                    ) : websiteAnalysis.result === "Error" ? (
                        <p className="warning"><strong>Invalid URL. Please enter a valid URL.</strong></p>
                    ) : (
                        <p className="safe">This URL appears to be safe.</p>
                    )}
                </div>
            )}
    </div>
  );
};

export default URLPhishing;