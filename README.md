## This Project is Deprecated
### But Project has been given an update on based on (10/1/2025)

GoDDos-Html is a lightweight web-page botnet controller written in Go, designed for simplicity by sending attacks to the 'Bots' / 'Servers' through a web-interface.

## Features
- **User Management:** Authenticate and Register.
- **Command Distribution:** Send distinct commands from the server to the bots.
- **Secure Authentication:** Utilizes password hashing and session management.
- **Easy Setup:** Straightforward steps to get started with minimal configuration.

## **Images / References 🖼️**
   `The images contain a domain: *Birdo.local*, which is a local domain set up for project testing.`

## Happy 2025, This issue has been fixed, ( 🤡 Lied about no Further updates )
###   [Misuse the ServerConfig.PublicKeyCallback callback] Go further down to read about.
  
### ***Dashboard***:
![dashgit2](https://github.com/Birdo1221/GoDDos-Html/assets/81320346/2858e11a-e3bf-4d37-a0c1-7ecc766b21a4)
![StartingGit2](https://github.com/Birdo1221/GoDDos-Html/assets/81320346/177dc1fa-ab30-4e49-bc6d-3d8807c77c2a)

### ***Register***:
![Registergit2](https://github.com/Birdo1221/GoDDos-Html/assets/81320346/69f3d100-12d4-4d2c-ab58-03a3b8af2eac)

### ***Login***:
![Logingit2](https://github.com/Birdo1221/GoDDos-Html/assets/81320346/24408d12-c45d-4df2-897a-6f651de58be7)

### ***Profile***:
![Profilegit2](https://github.com/Birdo1221/GoDDos-Html/assets/81320346/55e52bfa-112f-4354-9c87-2df5bd87acae)

### ***Index***:
![Logingit](https://github.com/Birdo1221/GoDDos-Html/assets/81320346/e9459072-2395-4cc1-944d-9fbcd10ac2de)

### Deprecation of Insecure Practic (Fixed 10/1/2025) 
This involves the misuse of `ServerConfig.PublicKeyCallback`, leading to an authorization bypass in `golang.org/x/crypto`. If the `PublicKeyCallback` function is implemented to return `nil, nil` unconditionally, it execute a successful authentication without validating the client's public key.

Although this was not an immediate issue in the project, it has been flagged for safety reasons. It's important to note that even minor vulnerabilities in code can lead to an unintended chain of issues. Therefore, it's get an update to help better security in the long term.

![image](https://github.com/user-attachments/assets/ed984ee0-8a6c-48ce-9c95-6db6b4ff2104)


## Getting Started

To deploy and use GoDDos-Html, follow these steps:

* You will need to set up the MySQL database before running the `./web-controller`.
* Change port and IP if needed on Line 35.

   ### 1. **Clone the Repository:**
   ```bash
   git clone https://github.com/Birdo1221/GoDDos-Html.git
   cd GoDDos-Html
   go build -o web-controller
   ./web-controller
   ```

# 2. **Mysql Set-up:**

   ```sql
   CREATE DATABASE IF NOT EXISTS net1;
   
   USE net1;
   CREATE TABLE IF NOT EXISTS users (
       id INT AUTO_INCREMENT PRIMARY KEY,
       username VARCHAR(50) UNIQUE NOT NULL,
       password_hash VARCHAR(60) NOT NULL
   );
   
   CREATE TABLE IF NOT EXISTS sessions (
       id INT AUTO_INCREMENT PRIMARY KEY,
       user_id INT NOT NULL,
       FOREIGN KEY (user_id) REFERENCES users(id),
       session_key VARCHAR(60) UNIQUE NOT NULL
   );
   ```

# 3. **Access the Web Interface:**
   - Open your web browser and navigate to http://localhost:80. If you change the IP/PORT, just head to that.
 
# 4. **Dependencies / Configuration:**
- **Go + MySQL:** Ensure Go and MySQL are installed and accessible.
- **Database Configuration:** Configure the database connection in the `initDB()` function.
  
# 5. **Usage:**
- Register a user account to access the controller dashboard.
- Login with your credentials to access the dashboard.
- Use the dashboard to send commands to connected bots.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
