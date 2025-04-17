# GoDDos-Html - Botnet Web Controller

![Project Logo](https://github.com/Birdo1221/GoDDos-Html/assets/81320346/2858e11a-e3bf-4d37-a0c1-7ecc766b21a4)

> **Note**: This project is deprecated but received a security update on 10/1/2025. It is maintained for educational purposes only.

## 📌 Overview

GoDDos-Html is a sophisticated web-based botnet controller written in Go, designed to manage distributed denial-of-service (DDoS) attacks through an intuitive web interface. The system features secure user authentication, command distribution to connected bots, and real-time monitoring capabilities.

**Disclaimer**: This software is provided for educational and research purposes only. Misuse of this software for unauthorized activities is strictly prohibited.

## 🚀 Features

### 🔒 Authentication System
- Secure user registration and login
- Argon2id password hashing
- Session management with secure cookies
- CSRF protection
- Rate limiting for login attempts
- Account lockout after failed attempts

### 🕹️ Botnet Control
- Real-time bot connection monitoring
- Command distribution to connected nodes
- Multiple attack methods (HTTP Flood, UDP Flood, TCP SYN Flood)
- Target validation (IP/port verification)
- Attack duration control

### 🛡️ Security
- Secure session storage
- Password complexity enforcement
- Input validation and sanitization
- Security headers (CSP, XSS Protection, etc.)
- IP address filtering (blocks private/local targets)

### 🎨 User Interface
- Retro 80s hacker-themed interface
- Responsive design
- Interactive dashboard
- Real-time statistics
- Activity logging
- Binary rain animation effect

## 📸 Screenshots

| Dashboard | Login | Register |
|-----------|-------|----------|
| ![Dashboard](https://github.com/Birdo1221/GoDDos-Html/assets/81320346/2858e11a-e3bf-4d37-a0c1-7ecc766b21a4) | ![Login](https://github.com/Birdo1221/GoDDos-Html/assets/81320346/24408d12-c45d-4df2-897a-6f651de58be7) | ![Register](https://github.com/Birdo1221/GoDDos-Html/assets/81320346/69f3d100-12d4-4d2c-ab58-03a3b8af2eac) |

| Profile | Command Interface |
|---------|-------------------|
| ![Profile](https://github.com/Birdo1221/GoDDos-Html/assets/81320346/55e52bfa-112f-4354-9c87-2df5bd87acae) | ![Command Interface](https://github.com/Birdo1221/GoDDos-Html/assets/81320346/e9459072-2395-4cc1-944d-9fbcd10ac2de) |

## ⚙️ Technical Architecture

### Backend Components
- **Web Server**: Go HTTP server with Gorilla toolkit
- **Authentication**: Session-based with secure cookies
- **Database**: JSON file storage (users.json)
- **Bot Communication**: TCP listener on port 9080
- **Security Middleware**: CSRF protection, rate limiting

### Frontend Components
- **Templates**: HTML with Go templating
- **Styling**: Custom CSS with neon effects
- **Animations**: Canvas-based binary rain
- **Interactive Elements**: JavaScript form validation

### Security Measures
- Password hashing with Argon2id
- Secure session management
- CSRF tokens for all forms
- Rate limiting for authentication endpoints
- Input validation for all commands
- IP address filtering

## 🛠️ Installation

### Prerequisites
- Go 1.20+ installed
- MySQL (optional for production)
- Basic firewall configuration

### Setup Instructions

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Birdo1221/GoDDos-Html.git
   cd GoDDos-Html
