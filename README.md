# GoDDos-Html - Botnet Web Controller
> **Note**: This project is deprecated but will try to maintain a security updates. It is mainly maintained for educational purposes  only.

## 📌 Overview

> **Note 2.0**: I have also updated this project so that is run on TLS / HTTPS, for that on lines 135 You will need to provide or create you own cert / key, easiest option would be via `openssl` or using `certbot` / `Letsencrypt`. And yes this is a fully working basic concept, with some example bots.

GoDDos-Html is your average web-based botnet controller written in Go, designed to manage distributed denial-of-service (DDoS) attacks through an intuitive web interface. The system features secure user authentication, command distribution to connected bots, and real-time monitoring capabilities.

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
- Multiple attack methods (HTTP Flood, UDP Flood, TCP SYN Flood)
- Target validation (IP/port verification)
- Attack duration control

## 📸 Screenshots

| Login | Register |
|-------|----------|
| ![Login](https://github.com/user-attachments/assets/311702c6-2534-4acb-b09a-abf52d619c99) | ![Register](https://github.com/user-attachments/assets/6d8953f6-bb2d-4c0c-a9a8-15e493aaafd2) |

| Profile | Dashboard |
|---------|-----------|
| ![Profile](https://github.com/user-attachments/assets/058cc9fa-0c3c-47e6-8664-9fd143ec434a) | ![Dashboard](https://github.com/user-attachments/assets/7a5a07f5-5449-4d3a-bd06-ef33ebbdcb18)

### 🛡️ Security
- Secure session storage
- Password complexity enforcement
- Input validation and sanitization
- Security headers (CSP, XSS Protection, etc.)
- IP address filtering (blocks private/local targets)

### 🎨 User Interface
- Retro 80s Groovy hacker-themed interface
- Responsive design
- Interactive dashboard
- Real-time statistics
- Activity logging


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
