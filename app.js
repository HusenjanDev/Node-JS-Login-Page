const express           = require('express');
const session           = require('express-session')
const expressLayouts    = require('express-ejs-layouts');
const localStratergy    = require('passport-local');
const passport          = require('passport');
const bcrypt            = require('bcrypt');
const mongoose          = require('mongoose');

// Moongose connection.
mongoose.connect('mongodb://127.0.0.1:27017/appdb');

// Mongoose User.
const User = require('./models/user');

// Express app.
const app = express();

// Middleware.
app.use(expressLayouts);
app.use(express.urlencoded( {extended : true} ));

// Express session.
app.use(session({
    secret : 'secret',
    resave : false,
    saveUninitialized : true
}))

// Passport.js
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    User.findById(id, (err, user) => {
        done(err, user);
    });
});

passport.use(new localStratergy( (username, password, done) => {
    User.findOne({ username : username }, (err, user) => {
        if (err) return done(err);
        if (!user) return done(null, false, { message : 'Incorrect username.'});

        bcrypt.compare(password, user.password, (err, res) => {
            if (err) return done(err);
            if (res === false) return done(null, false, { message : 'Incorrect password.'});

            return done(null, user);
        });
    });
}));

// Setting the view-port.
app.set('view engine', 'ejs');

// Login page.
app.get('/login', isLoggedOut, (req, res) => {
    res.render('login');
})

app.post('/login', passport.authenticate('local', {
    successRedirect : '/',
    failureRedirect : '/login'
}));

// Index page.
app.get('/', isLoggedIn, (req, res) => {
    res.render('index', { user : req.user.username });
})

// Register page.
app.get('/register', isLoggedOut, (req, res) => {
    res.render('register');
});

app.post('/register', async(req, res) => {
    if (req.body.username.length <= 3 || req.body.password.length <= 3)
    {
        res.send('Username and Password needs to be atleast 4 words.');
    }
    else 
    {
        var exist = await User.exists({username : req.body.username});

        if (exist == true) {
            res.send('User already exist!');
        }
        else 
        {
            bcrypt.genSalt(12, async(err, salt) => {
                if (err) throw err;
    
                bcrypt.hash(req.body.password, salt, async(err, hash) => {
                    if (err) throw err;
    
                    const NewUser = await new User({
                        username : req.body.username,
                        password : hash
                    });
    
                    await NewUser.save();
    
                    res.redirect('/login');
                });
            });
        }
    }
});

// Logout.
app.get('/logout', (req, res) => {
    req.logOut();
    res.redirect('/login');
});

// Starting the connection on port 3000.
app.listen(3000, () => {
    console.log('Listening on port 3000.');
});

// IsLoggedIn.
function isLoggedIn(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.redirect('/login');
}

// IsLoggedOut.
function isLoggedOut(req, res, next)
{
    if (!req.isAuthenticated()) return next();
    res.redirect('/')
}