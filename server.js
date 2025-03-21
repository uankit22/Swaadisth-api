require("dotenv").config();
const express = require("express");
const jwt = require("jsonwebtoken");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const port = process.env.PORT || 5000;

app.use(express.json());

// Supabase Connection
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// Function to Generate JWT Token
const generateToken = (user) => {
  return jwt.sign({ user_id: user.id, mobile: user.mobile_number }, process.env.JWT_SECRET, {
    expiresIn: "7d",
  });
};

// Middleware to Authenticate JWT Token
const authenticateToken = async (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) return res.status(401).json({ error: "Access Denied. No token provided." });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    let { data: user, error } = await supabase.from("users").select("*").eq("id", decoded.user_id).single();

    if (error || !user) return res.status(403).json({ error: "User not found or token invalid." });

    req.user_id = decoded.user_id;
    next();
  } catch (error) {
    return res.status(403).json({ error: "Invalid or Expired Token." });
  }
};

// ✅ Signup API
app.post("/signup", async (req, res) => {
  try {
    const { mobile_number, email, name } = req.body;

    if (!mobile_number || !email || !name) return res.status(400).json({ error: "All fields are required" });

    let { data: existingUser } = await supabase.from("users").select("*").eq("mobile_number", mobile_number).single();

    if (existingUser) return res.status(400).json({ error: "User already exists. Please log in." });

    const { data: newUser, error } = await supabase.from("users").insert([{ mobile_number, email, name }]).select().single();

    if (error) return res.status(500).json({ error: error.message });

    const token = generateToken(newUser);

    return res.status(201).json({ message: "Signup successful", token, user: newUser });
  } catch (error) {
    console.error("Signup error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// ✅ Login API
app.post("/login", async (req, res) => {
  try {
    const { mobile_number } = req.body;

    if (!mobile_number) return res.status(400).json({ error: "Mobile number is required" });

    let { data: user } = await supabase.from("users").select("*").eq("mobile_number", mobile_number).single();

    if (!user) return res.status(404).json({ error: "User not found. Please sign up." });

    const token = generateToken(user);
    return res.json({ message: "Login successful", token, user });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// ✅ Get User Details (Protected)
app.get("/user", authenticateToken, async (req, res) => {
  try {
    let { data: user, error } = await supabase
      .from("users")
      .select("*, addresses(*)")
      .eq("id", req.user_id)
      .single();

    if (error || !user) return res.status(404).json({ error: "User not found" });

    res.json({ user });
  } catch (error) {
    console.error("Error fetching user details:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// ✅ Add Address (Protected)
app.post("/address", authenticateToken, async (req, res) => {
  try {
    const { full_name, mobile_number, address_line1, address_line2, landmark, pincode, city, state, type } = req.body;

    const { data: address, error } = await supabase
      .from("addresses")
      .insert([{ user_id: req.user_id, full_name, mobile_number, address_line1, address_line2, landmark, pincode, city, state, type }])
      .select()
      .single();

    if (error) return res.status(500).json({ error: error.message });

    res.status(201).json({ message: "Address added successfully", address });
  } catch (error) {
    console.error("Error adding address:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// ✅ Edit Address (Protected)
app.put("/address/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { full_name, address_line1, address_line2, landmark, pincode, city, state, type } = req.body;

    const { data: updatedAddress, error } = await supabase
      .from("addresses")
      .update({ full_name, address_line1, address_line2, landmark, pincode, city, state, type })
      .eq("id", id)
      .eq("user_id", req.user_id)
      .select()
      .single();

    if (error) return res.status(404).json({ error: "Address not found or unauthorized access." });

    res.json({ message: "Address updated successfully", address: updatedAddress });
  } catch (error) {
    console.error("Error updating address:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// ✅ Delete Address (Protected)
app.delete("/address/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const { data, error } = await supabase.from("addresses").delete().eq("id", id).eq("user_id", req.user_id);

    if (error || !data) return res.status(404).json({ error: "Address not found or unauthorized" });

    res.json({ message: "Address deleted successfully" });
  } catch (error) {
    console.error("Error deleting address:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Start Server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
