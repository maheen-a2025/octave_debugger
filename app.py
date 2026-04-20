from flask import Flask, render_template, request, jsonify
from analyzer import analyze
import json

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze_code():
    data = request.get_json()
    code = data.get('code', '').strip()

    if not code:
        return jsonify({'error': 'No code provided'}), 400

    result = analyze(code)

    errors_payload = []
    for e in result.errors:
        errors_payload.append({
            'id': e.id,
            'line': e.line,
            'type': e.type,
            'description': e.description,
            'solution': e.solution,
            'severity': e.severity,
            'original_line': e.original_line,
            'fixed_line': e.fixed_line,
        })

    return jsonify({
        'errors': errors_payload,
        'corrected_code': result.corrected_code,
        'summary': result.summary,
    })


if __name__ == '__main__':
    print("🔬 OctaveDebug running at http://localhost:5000")
    app.run(debug=True, port=5000)
