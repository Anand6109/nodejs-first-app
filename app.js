const express = require('express');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const path = require('path'); // Import the path module
const app = express();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');


// Set the view engine to EJS
app.set('view engine', 'ejs');
// Set the path for views directory
app.set('views', path.join(__dirname, 'views'));

// Use cookie parser middleware
app.use(cookieParser());
app.use(express.static(path.join(path.resolve(), "public")));
app.use(bodyParser.urlencoded({ extended: true }));

mongoose.connect('mongodb://localhost:27017/login')
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.error('MongoDB connection error:', err));

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    }
});
const User = mongoose.model('User', userSchema);

const isAuthenticated = async (req, res, next) => {
    const { token } = req.cookies;
    if (token) {
        const decoded = jwt.verify(token, 'secreteee');
        req.user = await User.findById(decoded._id);
        next()
    } else {
        res.redirect('/login');
    }
};

app.get('/', isAuthenticated, (req, res) => {
    res.render('logout', { name: req.user.name });
});
app.get('/login', (req, res) => {
    res.render('login');
})


app.post('/login', async (req, res) => {
    const { email, password } = req.body; // Corrected destructuring syntax
    let user = await User.findOne({ email })
    if (!user) {
        return res.redirect('/register');
    }

    const ismatch = await bcrypt.compare(password, user.password);
    if (!ismatch) {
        return res.render('login', { email, message: "Incorrect password" })
    }

    const token = jwt.sign({ _id: user._id }, 'secreteee')
    res.cookie('token', token, { httpOnly: true });
    console.log('User saved to database:', user);
    console.log('User logged in');
    res.redirect('/');
});



app.post('/register', async (req, res) => {
    const { name, email, password } = req.body; // Corrected destructuring syntax
    let user = await User.findOne({ email })
    if (user) {
        return res.redirect('/login', { email });
    }

    const hashedpassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({
        name,
        email,
        password: hashedpassword
    });

    const token = jwt.sign({ _id: newUser._id }, 'secreteee')
    res.cookie('token', token, { httpOnly: true });
    console.log('User saved to database:', newUser);
    console.log('User logged in');
    res.redirect('/');


});


app.get('/register', (req, res) => {
    res.render('register');
})

// Route to handle logout button click
app.get('/logout', (req, res) => {
    // Clear the 'loggedIn' cookie
    res.clearCookie('token');
    console.log('User logged out');
    res.redirect('/'); // Redirect to home page after clearing the cookie
});
// Start the server
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
