const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const path = require('path');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Database connection
mongoose.connect('mongodb+srv://dbEsteemJK:qwerty786!A@esteem-jk.wwqurhe.mongodb.net/?retryWrites=true&w=majority&appName=Esteem-JK', { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("Database connection successful"))
  .catch(err => console.error("Database connection error:", err));

// Configure Nodemailer
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'mohamedathikr.22msc@kongu.edu',
    pass: 'vkff fnsy cfea qhun'
  }
});

// Dynamic schema and model function
const getUserModel = (organization) => {
  const userSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    password: String,
    age: Number,
    organization: String,
    otp: String,
    otpExpires: Date
  });

  userSchema.pre('save', function (next) {
    if (this.isModified('password')) {
      bcrypt.hash(this.password, 10, (err, hash) => {
        if (err) return next(err);
        this.password = hash;
        next();
      });
    } else {
      next();
    }
  });

  return mongoose.model(organization.toLowerCase().replace(/\s+/g, '_'), userSchema, organization.toLowerCase().replace(/\s+/g, '_'));
};

// Send OTP route
app.get('/send-otp', async (req, res) => {
  const { email, organization } = req.query;
  const otp = crypto.randomInt(100000, 999999).toString();
  const otpExpires = new Date(Date.now() + 15 * 60 * 1000); 

  const User = getUserModel(organization);

  try {
    const user = await User.findOneAndUpdate(
      { email },
      { otp, otpExpires },
      { new: true, upsert: true }
    );

    if (user) {
      const mailOptions = {
        from: 'your-email@gmail.com',
        to: email,
        subject: 'Your OTP Code',
        text: `Your OTP code is ${otp}. It is valid for 15 minutes.`
      };

      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.error('Error sending OTP:', error);
          res.status(500).json({ success: false, message: 'Failed to send OTP' });
        } else {
          res.json({ success: true });
        }
      });
    } else {
      res.status(400).json({ success: false, message: 'Failed to generate OTP' });
    }
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Verify OTP route
app.post('/verify-otp', async (req, res) => {
  const { email, otp, organization } = req.body;
  const User = getUserModel(organization);

  try {
    const user = await User.findOne({ email });
    if (user && user.otp === otp && new Date() <= user.otpExpires) {
      res.json({ success: true });
    } else {
      res.status(400).json({ success: false, message: 'Invalid or expired OTP' });
    }
  } catch (error) {
    console.error("Error verifying OTP:", error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// User signup route
app.post('/signup', async (req, res) => {
  const { name, email, password, age, otp, organization } = req.body;
  const collectionName = organization.toLowerCase().replace(/\s+/g, '_');
  const User = getUserModel(organization);

  try {
    const collections = await mongoose.connection.db.listCollections({ name: collectionName }).toArray();

    if (collections.length > 0) {
      console.log(`Organization '${organization}' exists, adding user to the collection.`);
    } else {
      console.log(`Organization '${organization}' does not exist, creating new collection.`);
    }

    const existingUser = await User.findOne({ email });

    // If the user does not exist
    if (!existingUser) {
      if (otp) {
        const newUser = new User({
          name,
          email,
          password,
          age,
          organization,
          otp, // Store OTP in case you need it
          otpExpires: new Date(Date.now() + 15 * 60 * 1000) // New expiry time for OTP
        });

        await newUser.save();
        console.log("User created successfully");
        return res.redirect('/front-end.html');
      } else {
        return res.status(400).send("OTP is required");
      }
    } else {
      // If the user exists, verify the OTP
      if (existingUser.otp !== otp || new Date() > existingUser.otpExpires) {
        return res.status(400).send("Invalid or expired OTP");
      }

      // Update user details if OTP is valid
      existingUser.name = name;
      existingUser.password = password; // This will trigger the password hash process in the pre-save hook
      existingUser.age = age;
      existingUser.organization = organization;

      await existingUser.save();
      console.log("User updated successfully");
      return res.redirect('/front-end.html');
    }
  } catch (error) {
    console.error("Error during signup:", error);
    res.status(500).send("Error during signup");
  }
});

// User login route
app.post('/login', (req, res) => {
  const { email, password, organization } = req.body;
  const User = getUserModel(organization);

  User.findOne({ email })
    .then(user => {
      if (user) {
        bcrypt.compare(password, user.password, (err, result) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            res.status(500).send("Error logging in");
          } else if (result) {
            res.redirect('/front-end.html');
          } else {
            res.status(401).send("Login Failed: Incorrect Email or Password");
          }
        });
      } else {
        res.status(401).send("Login Failed: Incorrect Email or Password");
      }
    })
    .catch(error => {
      console.error("Error logging in:", error);
      res.status(500).send("Error logging in");
    });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
