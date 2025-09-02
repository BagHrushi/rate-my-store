

const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");
const Admin = require("./models/Admin");


mongoose.connect("mongodb://127.0.0.1:27017/rate-my-store")
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB connection error:", err));

async function resetPassword() {
  try {
    const email = "admin@example.com";  
    const newPassword = "Admin@123";    

    
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    
    const admin = await Admin.findOneAndUpdate(
      { email },
      { password: hashedPassword },
      { new: true, upsert: true }
    );

    console.log("Password reset successful!");
    console.log("Email:", email);
    console.log("New Password (use this to login):", newPassword);

    mongoose.connection.close();
  } catch (error) {
    console.error("Error resetting password:", error);
    mongoose.connection.close();
  }
}

resetPassword();
