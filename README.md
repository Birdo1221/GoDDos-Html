## This project is Depreciated and Wont Recive further updates

Update : Deprecation of Insecure Practices
This involve the misuse of ServerConfig.PublicKeyCallback, leading to an authorization bypass in golang.org/x/crypto. If the PublicKeyCallback function is implemented to return nil, nil unconditionally, it signifies successful authentication without validating the client's public key. This has been noted for safety reasons for this project.

# GoDDos-Html

GoDDos-Html is a lightweight web-page botnet controller written in Go, designed for simplicity by sending attacks to the 'Bots' / 'Servers' through a web-interface.

## Features

- **User Management:** Authenticate and Register. 
- **Command Distribution:** Send Distinct commands from the server to the bots.
- **Secure Authentication:** Utilizes password hashing and session management.
- **Easy Setup:** Straightforward steps to get started with minimal configuration.

# **Images / References :🖼️**
## ***Dashboard***:
![dashgit2](https://github.com/Birdo1221/GoDDos-Html/assets/81320346/2858e11a-e3bf-4d37-a0c1-7ecc766b21a4)
![StartingGit2](https://github.com/Birdo1221/GoDDos-Html/assets/81320346/177dc1fa-ab30-4e49-bc6d-3d8807c77c2a)
# ***Register***:
![Registergit2](https://github.com/Birdo1221/GoDDos-Html/assets/81320346/69f3d100-12d4-4d2c-ab58-03a3b8af2eac)
## ***Login***:
![Logingit2](https://github.com/Birdo1221/GoDDos-Html/assets/81320346/24408d12-c45d-4df2-897a-6f651de58be7)
## ***Profile***:
![Profilegit2](https://github.com/Birdo1221/GoDDos-Html/assets/81320346/55e52bfa-112f-4354-9c87-2df5bd87acae)
## ***Index***:
![Logingit](https://github.com/Birdo1221/GoDDos-Html/assets/81320346/e9459072-2395-4cc1-944d-9fbcd10ac2de)


## Getting Started

To deploy and use GoDDos-Html, follow these steps:

*You will need to Setup the mysql Database before running the ./web-controller*
*Change Port and IP if need be on Line 35.*

# 1. **Clone the Repository:**
   
   ```
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

   Open your web browser and navigate to [http://localhost:80](http://localhost:80).
   If you change the IP:PORT just head to that.
   

# 4. **Dependencies / Configuration:**

   - **Go + MySQL:** Ensure Go and MySQL are installed and accessible.
   - **Database Configuration:** Configure the database connection in the `initDB()` function.

# 5. **Usage:**

   - Register a user account to access the controller dashboard.
   - Login with your credentials to access the dashboard.
   - Use the dashboard to send commands to connected bots.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
