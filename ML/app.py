import logging
from flask import Flask, request, jsonify
from flask_cors import CORS
from email_det import predict_email
from url_det import predict_url

# Configure Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Flask App
app = Flask(__name__)
CORS(app)

@app.route('/predict-url', methods=['POST'])
def predict_url_api():
    data = request.json
    url = data.get("URL", "")

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    # Call your phishing detection model
    result = predict_url(url)  # Get the dictionary from predict_url

    return jsonify(result) 

@app.route("/predict-email", methods=["POST"])
def predict_email_endpoint():
    try:
        data = request.get_json()
        email = data.get("email")
        if not email:
            return jsonify({"error": "No email provided"}), 400
        prediction_result = predict_email(email)
        return jsonify({"result": prediction_result})
    except Exception as e:
        logging.error(f"Error predicting email: {e}")
        return jsonify({"error": "Server error: " + str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)