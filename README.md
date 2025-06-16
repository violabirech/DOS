---
title: DoS Anomalies Detection
emoji: 🚀
colorFrom: red
colorTo: blue
sdk: gradio
sdk_version: 4.44.0
app_file: app.py
pinned: false
license: mit
tags:
  - machine-learning
  - cybersecurity
  - anomaly-detection
  - network-security
  - dos-detection
---

# 🚀 Advanced DoS Anomaly Detection System

A sophisticated machine learning-based system for detecting Denial of Service (DoS) attacks in real-time network traffic.

## 🌟 Features

- **Real-time Detection**: Instant analysis of network traffic patterns
- **Multiple Attack Types**: Detects DDoS floods, Slowloris, amplification attacks
- **REST API**: Easy integration with existing systems
- **Batch Processing**: Analyze large datasets via CSV upload
- **Interactive Interface**: User-friendly web interface for testing
- **Comprehensive Metrics**: Confidence scores, risk assessment, detailed analysis

## 🔧 Model Architecture

- **Algorithm**: Advanced Isolation Forest with feature engineering
- **Features**: Inter-arrival time, packet length
- **Training Data**: 5,000 synthetic network traffic samples
- **Performance**: <50ms processing time per prediction
- **Accuracy**: Optimized for network security applications

## 🚀 Quick Start

### Web Interface
1. Visit the Space URL
2. Enter network traffic parameters
3. Click "Analyze Traffic" for instant results
4. Use quick test buttons for common scenarios

### API Usage

**Endpoint**: `POST /predict`

```python
import requests

response = requests.post(
    "https://violabirech-dos-anomalies-detection.hf.space/predict",
    json={
        "inter_arrival_time": 0.001,  # Very fast packets
        "packet_length": 1400         # Large packets
    }
)

result = response.json()
print(f"Anomaly: {result['anomaly']}")
print(f"Risk Score: {result['risk_score']}")
print(f"Attack Type: {result['anomaly_type']}")
