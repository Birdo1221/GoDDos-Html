# GoDDos-Html

This is a simple web-page controller botnet written in Go. It allows you to control bots through a web interface. The botnet consists of a controller server and bots that connect to it.

## Features

- User authentication and authorization
- User registration
- User profile management
- Sending commands to bots
- Bot authentication
- Bot command execution

## Getting Started

To get started with this, follow these steps:

1. **Clone the Repository:**
   ```
   
   git clone https://github.com/your_username/web-page-controller-botnet.git
   cd web-page-controller-botnet
   go build
   ./web-page-controller
   ```
2. **Mysql Set-up**
   ```
   CREATE DATABASE IF NOT EXISTS net1

   USE net1
   
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

4. **Access the Web Interface:**
Open your web browser and go to http://localhost:80.

*Dependencies / Configuration*
    

  ```
    Go  +  MySQL

    Database: The botnet uses a MySQL database. You can configure the database connection in the 
    initDB() function

  ```

5. **Usage**
```
- Register a user account to access the controller dashboard.
- Login with your credentials to access the dashboard.
- From the dashboard, you can send commands to bots.
```

```
## Contributing

Contributions are welcome! If you have any ideas, improvements, or feature requests, feel free to open an issue or submit a pull request.

## License

This project is licensed under the [MIT License](LICENSE).
```




