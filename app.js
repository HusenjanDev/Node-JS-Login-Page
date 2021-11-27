const express           = require('express');
const flash             = require('express-flash');
const session           = require('express-session');
const expressLayouts    = require('express-ejs-layouts');
const localStratergy    = require('passport-local');
const passport          = require('passport');
const bcrypt            = require('bcrypt');
const mongoose          = require('mongoose');

/*
 * Connecting to mongoose database.
 */
mongoose.connect('mongodb://127.0.0.1:27017/appdb');


/*
 * Declaring and defining the User table created in /models/user.
 */
const User = require('./models/user');


/*
 * Creating the app from express().
 */
const app = express();


/*
 * Middlewares.
 */
app.use(expressLayouts);
app.use(express.urlencoded( {extended : true} ));
app.use(express.json());
app.use(flash());
app.use(session({
    secret : 'SuperSecretKey',
    resave : false,
    saveUninitialized : true
}))


/*
 * Preparing our passport.js.
 */
app.use(passport.initialize());
app.use(passport.session());


/*
 * Setting up the viewport.
 */
app.set('view engine', 'ejs');


/*
 * Passport.JS
 */
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    User.findById(id, (err, user) => {
        done(err, user);
    });
});


/*
 * The Passport.JS Authentication.
 */
passport.use(new localStratergy({
        passReqToCallback: true
    },
    (req, username, password, done) => {
        User.findOne({ username : username }, (err, user) => {
            if (err) return done(err);
            if (!user) return done(null, false, req.flash('error', 'Incorrect Username or Password.'));

            bcrypt.compare(password, user.password, (err, res) => {
                if (err) return done(err);
                if (res === false) return done(null, false, req.flash('error', 'Incorrect Username or Password.'));

                return done(null, user);
            });
        });
}));


/*
 * GET Request for our Login Page.
 */
app.get('/login', isLoggedOut, (req, res) => {
    const error= req.flash('error');

    res.render('login', { title : 'Login', error});
});


/*
 * POST Request for our Login Page.
 */
app.post('/login', (req, res) => {
    passport.authenticate('local', {
        successRedirect : '/',
        failureRedirect : '/login',
        failureFlash : true
    })(req, res);
});


/*
 * GET Request for our Dashboard Page.
 */
app.get('/', isLoggedIn, (req, res) => {
    res.render('index', { user : req.user.username, title : 'Dashboard' });
})


/* 
 * GET Request for our Registration Page.
 */
app.get('/register', isLoggedOut, (req, res) => {
    const username_length_error = req.flash('username_length_error');
    const password_length_error = req.flash('password_length_error');
    const exist_error = req.flash('exist_error');
    const username_invalid = req.flash('username_invalid')

    res.render('register', { title : 'Register', username_length_error, password_length_error, exist_error, username_invalid });
});


/*
 * POST Request for our Login Page.
 */
app.post('/register', async(req, res) => {
    // If USERNAME includes -*"_' then an error is displayed.
    if (req.body.username.includes('-') || req.body.username.includes('*') || req.body.username.includes('"') || req.body.username.includes('\'') || req.body.username.includes('_') )
    {
        req.flash('username_invalid', 'Username cannot have -*"_\'');
    }


    // If USERNAME length is less than 6 than an error is displayed.
    if (req.body.username.length <= 5)
    {
        req.flash('username_length_error', 'Username needs to be atleast 6 words!');
    }


    // If PASSWORD length is less than 6 than an error is displayed.
    if (req.body.password.length <= 5)
    {
        req.flash('password_length_error', 'Password needs to be atleast 6 words!');
    }


    // If USERNAME and PASSWORD is fine then the following statement is executed.
    if (req.body.username.length > 5 && req.body.password.length > 5 )
    {
        // Checking if the username is taken.
        var exist = await User.exists({username : req.body.username});

        // If the username is taken than an error is displayed.
        if (exist == true) {
            req.flash('exist_error', 'The user already exist!');
        }
        // Else we are creating the user.
        else 
        {
            // Generating the bcrypt salt.
            bcrypt.genSalt(12, async(err, salt) => {
                if (err) throw err;

                // Hashing the PASSWORD the user entered.
                bcrypt.hash(req.body.password, salt, async(err, hash) => {
                    if (err) throw err;

                    // Declaring the NewUser variable which holds the username and hashed password. 
                    const NewUser = await new User({
                        username : req.body.username,
                        password : hash
                    });

                    // Adding the user to the database table.
                    await NewUser.save();

                    // Redirecting the user after the creation was successfull.
                    res.redirect('/login');
                });
            });
        }
    }

    // Redirecting to Register Page.
    res.redirect('/register');

});


/*
 * GET Request for our Logout Page.
 */
app.get('/logout', (req, res) => {
    /*
     * The following code signs us out of the dashboard.
     */
    req.logOut();
    res.redirect('/login');
});


/*
 * Creating our connection on port 3000.
 */
app.listen(3000, () => {
    // Prints the message if everything ran successfully.
    console.log('Listening on port 3000.');
});


/*
 * isLoggedIn returns the user to the dashboard if the user tries to enter pages such as login and register.
 */
function isLoggedIn(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.redirect('/login');
}


/*
 * isLoggedOut returns the user to login.
 */
function isLoggedOut(req, res, next)
{
    if (!req.isAuthenticated()) return next();
    res.redirect('/')
}