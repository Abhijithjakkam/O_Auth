//jshint esversion:6
require('dotenv').config()
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const { setEngine } = require("crypto");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');


const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));

app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://0.0.0.0:27017/userDB");

const userSchema = new mongoose.Schema({
    email : String,
    password : String,
    googleId: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

// used to serialize the user for the session
passport.serializeUser(function(user, done) {
    done(null, user.id); 
   // where is this user.id going? Are we supposed to access this anywhere?
});

// used to deserialize the user
passport.deserializeUser(function(id, done) {
    User.findById(id)
    .then(user => {
    done(null, user);
    })
    .catch(err => {
    done(err, null);
    });
    });
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", (req, res)=>{
    res.render("home");
});

app.get("/auth/google",
    passport.authenticate("google", { scope: ["profile"] })
);

app.get("/auth/google/secrets", 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/secrets", (req, res)=>{
    if(req.isAuthenticated()){
        res.render("secrets");
    }else{
        res.redirect("/login");
    }
});


app.route("/register")
    .get((req, res)=>{
        res.render("register");
    })
    .post((req, res)=>{
        User.register(new User({username: req.body.username}), req.body.password)
            .then((user)=>{
                passport.authenticate("local")(req, res, ()=>{
                    res.redirect("/secrets");
                });
            })
            .catch((error)=>{
                console.log(error);
                res.redirect("/register");
            });
    });
app.route("/login")
    .get((req, res)=>{
    res.render("login");
    })
    .post((req, res)=>{
        const user = new User({
            username: req.body.username,
            password: req.body.password
        });

        req.login(user, (error)=>{
            if(error){
                console.log(error);
            }else{
                passport.authenticate("local")(req,res, ()=>{
                    res.redirect("/secrets");
                });
            }
        })
    })

    app.get("/logout", (req, res)=>{
        req.logout(function(err) {
          if (err) {
            console.log(err);
          }
          res.redirect("/");
        });
      });

app.listen(3000, (req, res)=>{
    console.log("Server Started on port 3000");
})
