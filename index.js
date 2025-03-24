import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";
import dotenv from "dotenv";



const app = express();
const port = 3000;
const saltRounds = 10;
dotenv.config();

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);


app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT
});
db.connect();

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
    res.render("login.ejs");
  });
  
  app.get("/Register", (req, res) => {
    res.render("register.ejs");
  });
  
  app.get("/logout", (req, res, next) => {
    req.logout(function (err) {
      if (err) {
        return next(err);
      }
      res.redirect("/");
    });
  });

  app.get("/secrets", (req, res) => {
    console.log(req.user); // Debugging: prints user info
  
    if (req.isAuthenticated()) {
      res.render("secrets.ejs");
    } else {
      res.redirect("/login");
    }
  });
  
  app.get(
    "/auth/google/callback",
    passport.authenticate("google", { failureRedirect: "/" }),
    (req, res) => {
      res.redirect("/dashboard"); // Амжилттай бол dashboard руу
    }
  );

  app.get(
    "/auth/google/secrets",
    passport.authenticate("google", {
      successRedirect: "/secrets",
      failureRedirect: "/login",
    })
  );
  

  app.post(
    "/login",
    passport.authenticate("local", {
      successRedirect: "/secrets",
      failureRedirect: "/login",
    })
  );

  app.post("/register",async(req,res)=>{
    const email = req.body.email;
    const password = req.body.password;

try {
  const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
    email,
  ]);

  if (checkResult.rows.length > 0) {
    res.redirect("/login");
  } else {
    bcrypt.hash(password, saltRounds, async (err, hash) => {
      if (err) {
        console.error("Error hashing password:", err);
      } else {
        
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );

          const user = result.rows[0];
          req.login(user, (err) => {
            console.log("success");
            res.redirect("/secret");
          });
    
      }
    });
  }
} catch (err) {
  console.log(err);
}
  });

passport.use(
    new Strategy(async function verify(username, password, cb) {
      try {
        // Query database for user
        const result = await db.query("SELECT * FROM users WHERE email = $1", [username]);
  
        if (result.rows.length > 0) {
          const user = result.rows[0];
          const storedHashedPassword = user.password;
  
          bcrypt.compare(password, storedHashedPassword, (err, valid) => {
            if (err) {
              console.error("Error checking password:", err);
              return cb(err);
            }
            if (valid) {
              return cb(null, user);
            } else {
              return cb(null, false);
            }
          });
        } else {
          return cb("User not found"); 
        }
      } catch (err) {
        console.log(err)
      }
    })
  );
  passport.serializeUser((user, cb) => {
    cb(null, user);
    });
    passport.deserializeUser((user, cb) => {
    cb(null, user);
    });
    app.listen(port, () => {
    console.log(`Server running on port ${port}`);
    });