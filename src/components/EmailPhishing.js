import { useEffect, useState } from "react";
import axios from "axios";
import { gapi } from "gapi-script";
import "../App.css";

const CLIENT_ID = "855638036836-6mnstrih78e0gfh206u6rpka1u7741ue.apps.googleusercontent.com";
const API_KEY = "AIzaSyD6qQ-aeHOSS1KD_gTj4lc14b57BJHKBug"; // Replace with your actual API key
const SCOPES = "https://www.googleapis.com/auth/gmail.readonly";

const EmailPhishing = () => {
  const [emails, setEmails] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    const loadGoogleLibraries = () => {
      const script = document.createElement("script");
      script.src = "https://accounts.google.com/gsi/client";
      script.async = true;
      script.defer = true;
      document.body.appendChild(script);

      script.onload = () => {
        console.log("Google Identity Services loaded.");
      };

      script.onerror = () => {
        console.error("Failed to load Google Identity Services.");
      };
    };

    const initClient = () => {
      gapi.load("client", () => {
        gapi.client
          .init({
            apiKey: API_KEY,
            clientId: CLIENT_ID,
            scope: SCOPES,
            discoveryDocs: [
              "https://www.googleapis.com/discovery/v1/apis/gmail/v1/rest",
            ],
          })
          .then(() => {
            console.log("Google API Initialized");
          })
          .catch((err) => {
            console.error("Error initializing Google API:", err);
          });
      });
    };

    loadGoogleLibraries();
    initClient();
  }, []);

  // Function to analyze emails for phishing
  const analyzeEmails = async (emailText) => {
    try {
      const response = await axios.post(
        "http://127.0.0.1:5000/predict-email", // Correct port number
        { email: emailText },
        { headers: { "Content-Type": "application/json" } }
      );
      return response.data.result; // "Phishing Email" or "Safe Email"
    } catch (err) {
      console.error("Error analyzing email:", err);
      return "Analysis Failed";
    }
  };

  const signInAndFetchEmails = async () => {
    setLoading(true);
    setError(null);

    try {
      if (!window.google) {
        throw new Error("Google library not loaded.");
      }

      const tokenClient = window.google.accounts.oauth2.initTokenClient({
        client_id: CLIENT_ID,
        scope: SCOPES,
        callback: async (tokenResponse) => {
          if (!tokenResponse || !tokenResponse.access_token) {
            throw new Error("Authentication failed.");
          }

          const token = tokenResponse.access_token;

          // Fetch latest emails
          const response = await axios.get(
            "https://www.googleapis.com/gmail/v1/users/me/messages",
            {
              headers: { Authorization: `Bearer ${token}` }, // Correct header
            }
          );

          if (!response.data.messages) {
            setError("No emails found.");
            return;
          }

          const messages = response.data.messages.slice(0, 14); // Get latest 15 emails

          // Fetch and analyze each email
          const emailDetails = await Promise.all(
            messages.map(async (msg) => {
              const emailData = await axios.get(
                `https://www.googleapis.com/gmail/v1/users/me/messages/${msg.id}?format=full`,
                {
                    headers: { Authorization: `Bearer ${token}` },
                }
            );
            //Then you will need to parse the payload to get the email body.
              const emailText = emailData.data.snippet;
              const result = await analyzeEmails(emailText);
              return { text: emailText, result };
            })
          );

          setEmails(emailDetails);
          setLoading(false); // Make sure to set loading to false.
        },
      });

      tokenClient.requestAccessToken();
    } catch (err) {
      console.error("Error fetching emails:", err);
      setError(err.message || "Failed to fetch emails."); // Display error message.
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="email-container">
      <h1>Email Phishing Detector</h1>
      <button onClick={signInAndFetchEmails} disabled={loading}>
        {loading ? "Fetching Emails..." : "Fetch Gmail Emails"}
      </button>
      {error && <p style={{ color: "red" }}>{error}</p>}

      <div className="email-list">
        {emails.map((email, index) => (
          <div key={index} className={`email-card ${email.result === "Phishing Email" ? "phishing" : "safe"}`}>
            <h3>{email.result}</h3>
            <p>{email.text}</p>
          </div>
        ))}
      </div>
    </div>
  );
};

export default EmailPhishing;