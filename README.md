# 🚀 OWASP Top 10 Training Portal

The **OWASP Top 10 Training Portal** is an educational web application designed to help users learn about the OWASP Top 10 web application security risks. It provides interactive challenges and detailed explanations for each vulnerability.

## 🔥 Features

- 📖 **Detailed explanations** of all **OWASP Top 10 (2021)** security vulnerabilities
- 🎯 **Interactive challenges** to test understanding of each vulnerability
- ⚠️ **Vulnerable code examples** demonstrating security mistakes
- ✅ **Secure code examples** showcasing proper mitigation techniques
- 🔑 **User registration and authentication** system
- 🔄 **Password recovery** functionality
- 📊 **Progress tracking** and statistics dashboard
- 🛠️ **Admin panel** for user management

## 🏗️ Technical Details

- 🎨 **Frontend:** HTML, CSS, JavaScript
- ⚙️ **Backend:** Node.js with Express
- 🗂️ **Storage:** Simple file-based storage for user data and statistics
- 🌍 **Deployment:** Can run in client-only mode or with a server for persistent storage
- 🐳 **Docker Support:** Dockerized deployment option available

## 🔐 OWASP Top 10 (2021) Covered

1. 🔓 **Broken Access Control**
2. 🔑 **Cryptographic Failures**
3. 💉 **Injection**
4. 🎭 **Insecure Design**
5. ⚙️ **Security Misconfiguration**
6. 🧩 **Vulnerable and Outdated Components**
7. 🆔 **Identification and Authentication Failures**
8. 🔄 **Software and Data Integrity Failures**
9. 📜 **Security Logging and Monitoring Failures**
10. 🌐 **Server-Side Request Forgery (SSRF)**

## 🛠️ Installation

### 📌 Prerequisites

- 🟢 Node.js (latest LTS recommended)
- 🐳 Docker (optional for containerized deployment)

### 📥 Steps

1. 📂 Clone the repository:
   ```sh
   git clone https://github.com/yourusername/owasp-top10-training-portal.git
   cd owasp-top10-training-portal
   ```
2. 📦 Install dependencies:
   ```sh
   npm install
   ```
3. ▶️ Run the application:
   ```sh
   npm start
   ```

### 🐳 Docker Deployment

To run using Docker:

```sh
docker build -t owasp-training .
docker run -p 3000:3000 owasp-training
Or
docker-compose up -d
```

## 📌 Usage

- 🌐 Open `http://localhost:3000` in your browser.
- 🔑 Register an account and start exploring the OWASP Top 10 vulnerabilities.
- 🎯 Use the interactive challenges to test your understanding.

## 🤝 Contributing

Contributions are welcome! If you'd like to improve the project, feel free to submit an issue or pull request.

## 📜 License

This project is licensed under the [MIT License](LICENSE).

## ⚠️ Disclaimer

This application is designed purely for **educational purposes** to help developers understand web security vulnerabilities and learn proper implementation techniques. Do **not** deploy this application in a production environment.

---

### 📢 Stay Updated

Follow [OWASP](https://owasp.org) for the latest security trends and best practices. 🚀

