# Store Rating Platform 🏬⭐

A full-stack web application where users can register, log in, and rate stores on a scale of **1 to 5**.  
The platform supports multiple user roles (**System Administrator, Normal User, Store Owner**) with different access levels and dashboards.

---

## 🚀 Tech Stack
- **Frontend**: React.js  
- **Backend**: Express.js / Loopback / NestJS (your chosen one)  
- **Database**: PostgreSQL / MySQL  

---

## 🔑 User Roles & Features

### 👨‍💼 System Administrator
- Add new stores, normal users, and admin users.  
- Dashboard showing:
  - Total number of users  
  - Total number of stores  
  - Total number of submitted ratings  
- Manage users and stores (with filters: Name, Email, Address, Role).  
- View details of all users and stores.  

### 🙍 Normal User
- Sign up and log in.  
- Update password after login.  
- View list of all registered stores.  
- Search stores by **Name** and **Address**.  
- Submit and update ratings (1–5) for stores.  

### 🏪 Store Owner
- Log in and update password.  
- Dashboard:
  - View users who rated their store  
  - See the **average rating** of their store  

---

## ✅ Form Validations
- **Name**: 10–60 characters  
- **Address**: up to 400 characters  
- **Password**: 8–16 characters, must include at least 1 uppercase letter & 1 special character  
- **Email**: Must be valid  

---









