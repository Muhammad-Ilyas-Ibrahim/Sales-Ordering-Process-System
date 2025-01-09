# Project: Sales Ordering Process System

## Overview

The Sales Ordering Process System is a web-based application designed to streamline the management of client orders, stock, deliveries, invoices, and reports. It provides an intuitive interface for users to interact with the system, enabling efficient handling of sales processes within an organization.

## Features

### 1. **User Management**
   - **Registration and Login**: Users can register and log in to the system. The registration process includes validation of password strength and confirmation to ensure secure user accounts.
   - **Password Security**: Passwords are securely stored in the database using hashing and salting techniques to protect user data (detailed in the Security section below).

### 2. **Client Management**
   - **Client Database**: Users can add, edit, and manage client information within the system. This includes storing details such as client names, addresses, and contact information.
   - **Search Functionality**: Users can easily search for specific clients using the search functionality.

### 3. **Stock Management**
   - **Inventory Tracking**: The system allows users to manage and track stock levels. Users can add new stock, update existing stock, and monitor stock levels.
   - **Low Stock Alerts**: The system can alert users when stock levels fall below a predefined threshold.

### 4. **Order Management**
   - **Order Creation and Tracking**: Users can create new orders, track the status of existing orders, and view order history.
   - **Order Details**: Detailed information about each order, including items, quantities, prices, and delivery status, is available to users.

### 5. **Delivery Management**
   - **Delivery Scheduling**: The system allows users to schedule deliveries for orders and track the delivery status.
   - **Delivery Confirmation**: Users can confirm the completion of deliveries and update the status within the system.

### 6. **Invoice Management**
   - **Invoice Generation**: Users can generate invoices for orders and send them to clients.
   - **Invoice Tracking**: The system provides tools for tracking the status of invoices, including payment status and due dates.

### 7. **Reporting**
   - **Sales Reports**: Users can generate reports on sales, orders, and stock levels to gain insights into the business performance.
   - **Export Options**: Reports can be exported in various formats (e.g., PDF, CSV) for further analysis.

## Security Features

### Password Security

- **Hashed Passwords**: To ensure that user passwords are securely stored, the system uses hashing techniques. This means that the actual password is not stored in the database; instead, a hash of the password is stored.
  
- **Salting**: To further enhance security, a unique salt is added to each password before hashing. This ensures that even if two users have the same password, their hashes will be different, making it more difficult for attackers to crack the passwords.

### Session Management

- **Session Cookies**: The system uses secure session cookies to manage user sessions. These cookies are encrypted to prevent unauthorized access.

- **Session Expiration**: User sessions automatically expire after a period of inactivity to reduce the risk of unauthorized access.

## Setting Up Google reCaptcha and Email Sending Feature

### 1. **Google reCaptcha Setup**
   - To enable Google reCaptcha, you need to obtain a secret key from the Google reCaptcha admin console.
   - **How to Get the Secret Key**: [Watch this video on YouTube](#) (will be available soon) to learn how to get your secret key for Google reCaptcha.

### 2. **Email Sending Feature Setup**
   - To enable the email-sending feature, you need to provide your email username and password in the configuration.
   - **How to Get the Email Password**: [Watch this video on YouTube](#) (will be available soon) to learn how to get the password for enabling email sending in the system.

## Technologies Used

- **Backend**: Flask (Python) - Handles the server-side logic, database interactions, and user authentication.
- **Frontend**: HTML, CSS, JavaScript - Provides the user interface and client-side functionality.
- **Database**: SQLite (or other SQL databases) - Stores user data, client information, orders, stock details, and more.
- **Hashing Algorithm**: Uses secure algorithms (like bcrypt) for hashing passwords.

## How to Run the Project

1. **Clone the Repository**: 
   ```bash
   git clone https://github.com/Muhammad-Ilyas-Ibrahim/sales-ordering-system.git
   ```

2. **Install Dependencies**: 
   ```bash
   pip install -r requirements.txt
   ```

3. **Set Up the Database**:
   - Run the provided script to initialize the database.
   ```bash
   python setup_db.py
   ```

4. **Run the Flask Application**:
   ```bash
   python app.py
   ```

5. **Access the System**: 
   - Open your browser and go to `http://localhost:5000` to start using the system.

## Folder Structure

- `app.py`: Contains the main application logic and routes.
- `static/`: Contains static files like CSS, JavaScript, and images.
- `templates/`: Contains HTML templates for rendering web pages.
- `database/`: Contains the database files and schema.

## Conclusion

The Sales Ordering Process System provides a robust solution for managing sales processes within an organization. With features like client management, order tracking, and invoice generation, it helps businesses stay organized and efficient. Additionally, the system takes security seriously by implementing hashed and salted password storage, secure session management, and more.
