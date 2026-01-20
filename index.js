import passport from "passport";
import dotenv from "dotenv";
dotenv.config();
console.log("DB URL loaded:", !!process.env.DATABASE_URL);
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import express from "express";
import session from "express-session";
import pg from "pg";
import bcrypt from "bcrypt";
import multer from "multer";
import path from "path";
import { fileURLToPath } from "url";
import axios from "axios";
import FormData from "form-data";
import pgSession from "connect-pg-simple"
import { CloudinaryStorage } from "multer-storage-cloudinary";
import cloudinary from "./config/cloudinary.js";


const ML_API = process.env.ML_API_CONNECT;

const app = express();
const port = process.env.PORT || 3000;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

const PgSession = pgSession(session);

const db = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

app.set("trust proxy", 1);

app.use(
  session({
    store: new PgSession({
      pool: db,        // your pg client
      tableName: "session",
    }),
    secret: process.env.SECRETKEY,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        maxAge: 1000 * 60 * 60 * 24, // 1 day
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());



passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const result = await db.query(
      "SELECT * FROM users WHERE id = $1",
      [id]
    );
    done(null, result.rows[0]);
  } catch (err) {
    done(err);
  }
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "/auth/google/callback",
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails[0].value;
        const name = profile.displayName;
        const googleId = profile.id;

        // check if citizen already exists
        const existing = await db.query(
          "SELECT * FROM users WHERE google_id = $1",
          [googleId]
        );

        if (existing.rows.length > 0) {
          return done(null, existing.rows[0]);
        }

        // create new citizen
        const newUser = await db.query(
          `INSERT INTO users (name, email, google_id, role)
           VALUES ($1, $2, $3, 'citizen')
           RETURNING *`,
          [name, email, googleId]
        );

        return done(null, newUser.rows[0]);
      } catch (err) {
        return done(err);
      }
    }
  )
);

const storage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: "civic-ai/complaints",
    allowed_formats: ["jpg", "jpeg"],
    resource_type: "image",
  },
});

const upload = multer({ storage });



function isCitizen(req, res, next){
    if(req.session.userId && req.session.role == "citizen") return next();
    else{
        res.render("loginAuthority.ejs", {errorMessage: "User Logged Out"});
    }
}

function isAuthenticated(req, res, next){
    if(req.session.userId) return next();
    else{
        res.render("loginAuthority.ejs", {errorMessage: "User Logged Out"});
        
    }
}

function isAuthority(req, res, next) {
  if (req.session.userId && req.session.role === "authority") {
    return next();
  }
  else{
    res.render("loginAuthority.ejs", {errorMessage: "User Logged Out"});
    
  }
}



app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    failureRedirect: "/",
  }),
  (req, res) => {
    req.session.userId = req.user.id;
    req.session.role = "citizen";
    res.redirect("/complaintDashboard");
  }
);

app.get("/", (req, res) =>{
    res.sendFile(path.join(__dirname, "public", "homePage.html"));
    
})


app.get("/signup/authority", (req, res) =>{
    res.render("signupAuthority.ejs");
})

app.post("/signup/authority", async (req, res) => {
    try{
        const email = req.body.email;
        const name = req.body.name;
        const pass = req.body.password;
        const security = req.body.code;

        if(security != process.env.ADMINLOGIN){
            return res.render("signupAuthority.ejs", {errorMessage: "Invalid security code"});
        }
        if(!email || !pass || !name) return res.render("signupAuthority.ejs", {errorMessage: "Missing required fields"});

        else{
            //register user
            const result = await db.query("SELECT * from users WHERE email = $1", [email]);
            if(result.rows.length){
               return res.render("signupAuthority.ejs", {errorMessage: "User already exists"});
            }
            else{
                const hashedPass = await bcrypt.hash(pass, 10);
                const role = "authority";
                await db.query("INSERT into users(email, name, password_hash, role) values($1, $2, $3, $4)", [email, name, hashedPass, role]);

                const data = await db.query("SELECT * from users WHERE email = $1", [email]);
                const userID = data.rows[0].id;

                req.session.userId = userID;
                req.session.email =  email;
                req.session.role = "authority";
                //redirect to authority dashboard;
                res.redirect("/authorityDashboard");
            }
        }
    }
    catch(err){
        console.error(err);
    }
})

app.get("/login/citizen", (req, res)=>{
    res.render("loginCitizen.ejs");
})

app.get("/signup/citizen", (req, res)=>{
    res.render("signupCitizen.ejs");
})


app.get("/login/authority", (req, res) =>{
    res.render("loginAuthority.ejs")
})
app.post("/login/authority", async (req, res) =>{
    const email = req.body.email;
    const pass = req.body.password;
    
    

    //confirm username and password

    if(!email || !pass) return res.render("loginAuthority.ejs", {errorMessage: "Missing required fields"});
    

    try{
        //extract the username field from users table
        const result = await db.query("SELECT * from users WHERE email = $1 AND role = 'authority'", [email]);
        if(result.rows.length == 0) return res.render("loginAuthority.ejs", {errorMessage : "email not found"});
        else{
            const hashedPass = result.rows[0].password_hash;
            const match = await bcrypt.compare(pass, hashedPass);
            if(!match){
                return res.render("loginAuthority.ejs", {errorMessage: "Invalid password"});
            }
            else{
                req.session.userId = result.rows[0].id;
                req.session.email = email;
                req.session.role = "authority";

                res.redirect("/authorityDashboard");

            }
        }
    }
    catch(err){
        console.error(err);
    }
})

//User has been authenticated as either citizen or authority until here

app.get("/complaintDashboard", isCitizen, async (req, res) =>{
    const result = await db.query(`SELECT * from users WHERE id = $1`, [req.session.userId]);
    if(result.rows.length==0) return res.status(503).send("Sever Error");
    const name = result.rows[0].name;
    res.render("complaintForm.ejs", {name: name});
})
app.post("/complaints", isCitizen,upload.single("image"), async(req, res) =>{
    const {description, location} = req.body;

    const result = await db.query(`SELECT * from users WHERE id = $1`, [req.session.userId]);
    if(result.rows.length==0) return res.status(503).send("Sever Error");
    const name = result.rows[0].name;

    if(!description || !location){
        return res.render("complaintForm.ejs", {name: name, errorMessage: "Missing required fields"})
    }
    if (!req.file) {
        return res.render("complaintForm.ejs", {name: name, errorMessage: "Only JPG/JPEG images allowed"})
    }

    try {
    const formData = new FormData();
    formData.append("image_url", req.file.path);


    formData.append("text", description);
    formData.append("location", location);

    
    const mlResponse = await axios.post(ML_API, formData, {
      headers: formData.getHeaders(),
      timeout: 30000, 
    });

    const issue = mlResponse.data.issue;
    const priority = mlResponse.data.priority.toLowerCase();
    const priority_score = mlResponse.data.priority_score;
    const solution = mlResponse.data.solution;


    const imageURL = req.file.path;
    const data = await db.query(
      `INSERT INTO complaints (user_id, description, image_url, location, issue_type, priority, priority_score, suggested_solution)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
      [req.session.userId, description, imageURL, location, issue, priority, priority_score, solution]
    );

    const cId = data.rows[0].id;


    //return success message
    res.render("successfullSubmission.ejs", {name: name, cId: cId});
    }
    catch(err){
        console.error(err);
    }
    
})


app.get("/citizenViewComplaints", isCitizen, async (req, res) =>{
    const { rows: complaints } = await db.query(
      `
      SELECT id, description, location, status
      FROM complaints
      WHERE user_id = $1
      ORDER BY created_at DESC
      `,
      [req.session.userId]
    );

    const counts = {
      reviewed: 0,
      progress: 0,
      resolved: 0,
    };

    complaints.forEach(c => {
      if (c.status === "registered") counts.reviewed++;
      else if (c.status === "in progress") counts.progress++;
      else if (c.status === "resolved") counts.resolved++;
    });

    const result = await db.query(`SELECT * from users WHERE id = $1`, [req.session.userId]);
    if(result.rows.length==0) return res.status(503).send("Sever Error");
    const name = result.rows[0].name;


    res.render("citizenViewComplaints.ejs", {
        name: name,
        complaints, counts
    });
})

app.get("/authorityDashboard", isAuthority, async(req, res)=>{

    try{
        const result = await db.query(`SELECT * from users WHERE id = $1`, [req.session.userId]);
        if(result.rows.length==0) return res.status(503).send("Sever Error");
        const name = result.rows[0].name;

        const {rows : complaints} = await db.query(`SELECT id, issue_type, priority, status, created_at::date AS created_date FROM complaints WHERE resolved_at IS NULL ORDER BY priority_score DESC`);
        const stats = {
            high: complaints.filter(c => c.priority === "high").length,
            low: complaints.filter(c => c.priority === "low").length,
            medium: complaints.filter(c => c.priority === "medium").length,
            unresolved: complaints.filter(c => c.status !== "resolved").length
        }

        res.render("authorityDashboard.ejs", {
            complaints, stats, name
        });
    }
    catch(err){
        console.error(err);
    }
})

app.get("/complaints/:id", isAuthority, async(req, res)=>{
    try{
        const complaintId = req.params.id;

        const {rows} = await db.query(`SELECT id, image_url, suggested_solution, description, location, status, issue_type, priority, created_at::date AS created_date FROM complaints WHERE id = $1`, [complaintId]);
        if(rows.length===0) res.redirect("/authorityDashboard");

        const complaint = rows[0];


        const result = await db.query(`SELECT * from users WHERE id = $1`, [req.session.userId]);
        if(result.rows.length==0) return res.status(503).send("Sever Error");
        const name = result.rows[0].name;

        res.render("complaint.ejs", {complaint, name: name});
    }
    catch(err){
        console.error(err);
    }
})

app.post("/updateStatus", isAuthority, async(req, res)=>{
    try{
        const cId = req.body.id;

        const result = await db.query(`SELECT * from complaints where id = $1`, [cId]);
        const currentStatus = result.rows[0].status;

        let newStatus;
        if(currentStatus==="registered") newStatus = "in progress";
        else if(currentStatus==="in progress") newStatus = "resolved";

        if(!newStatus) return res.redirect(`/complaints/${cId}`);

        await db.query(`UPDATE complaints
            SET status = $1 WHERE id = $2`, [newStatus, cId]);
            
        res.redirect(`/complaints/${cId}`);
    }
    catch(err){
        console.error(err);
    }
})

app.get("/authorityDashboard/:status", async(req, res)=>{
    try{
        let status = req.params.status;
        if(status==="inProgress") status = "in progress";

        const result = await db.query(`SELECT * from users WHERE id = $1`, [req.session.userId]);
        if(result.rows.length==0) return res.status(503).send("Sever Error");
        const name = result.rows[0].name;

        const {rows : complaints} = await db.query(`SELECT id, issue_type, priority, status, created_at::date AS created_date FROM complaints WHERE status = $1 ORDER BY priority_score DESC`, [status]);
        const stats = {
            high: complaints.filter(c => c.priority === "high").length,
            low: complaints.filter(c => c.priority === "low").length,
            medium: complaints.filter(c => c.priority === "medium").length,
            unresolved: complaints.filter(c => c.status !== "resolved").length
        }

        res.render("authorityDashboard.ejs", {
            complaints, stats, name
        });
    }
    catch(err){
        console.error(err);
    }
})

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});