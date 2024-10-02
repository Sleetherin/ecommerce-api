require('dotenv').config();
const express = require('express');
const pool = require('./db');
const bcrypt = require('bcrypt');

/**import passport for logging in */
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session');

const app = express();
const port = process.env.PORT || 3000;



/**Middleware to parse JSON bodies */
app.use(express.json());

app.get('/', (req,res) => {
    res.send('Testing the fourth project');
});

/**Getting all the users */
app.get('/users', async (req,res) => {
    try{
        const result = await pool.query('SELECT username FROM users');
        res.json(result.rows);
    }
    catch(err)
    {
        console.error(err);
        res.status(500).send(`${err}`);
    }
});



/**Get new users registered */
app.post('/register', async (req,res) => {
    try{
       /** registering new user - they must provide username,email,password */
       const {username, email, password} = req.body;

       if(!username || !email || !password )
       {
          return res.status(400).json({message: 'All fields are required'});
       }

       /**We check if the username or email already exists*/
       const existingUserQuery = 'SELECT 1 FROM users WHERE username = $1 OR email = $2';
       const existingUserResult = await pool.query(existingUserQuery, [username, email]);
       if(existingUserResult.rows.length > 0)
       {
          return res.status(400).json({message: 'Either username or email already exists'});
       }

       /** We check if the email is valid*/
       const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
       if (!emailRegex.test(email)) {
        return res.status(400).json({ message: 'Invalid email format' });
       }


       /**Hash the password */
       const saltRounds = 9;
       const hashedPassword = await bcrypt.hash(password, saltRounds);

       /**Insert the new user into the database */
       const insertUserQuery = `
       INSERT INTO users(username,password,email)
       VALUES ($1, $2, $3) RETURNING user_id,username,email
       `;
       const result = await pool.query(insertUserQuery, [username,hashedPassword,email]);


       /**Show the data excluding the password*/
       const newUser = result.rows[0];
       res.status(201).json({
          message:'User registered successfully',
          user: {
            user_id: newUser.user_id,
            username: newUser.username,
            email:newUser.email,
          }
       })
    }
    catch(error)
    {
        res.status(500).json({message: `Internal Server Error: ${error}`});
    }
})

/**Help old users log in*/

/**Express session middleware */
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 24 //this would be the whole day
  }
}))

/**Initialize passport */
app.use(passport.initialize());
app.use(passport.session()); 

/**Use the passport */
passport.use(new LocalStrategy(
  async (username, password, done) => {
    try{
      const query = 'SELECT * FROM users WHERE username = $1';
      const { rows } = await pool.query(query, [username]);
      if (rows.length === 0) {
        return done(null, false, { message: 'Incorrect username.' });
      }

      const user = rows[0];

      /**Is it a match? */
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return done(null, false, { message: 'Incorrect password.' });
      }

      /**If the authentication is successful */
      return done(null, user);

    } catch(err)
    {
      return done(err);
    }
  }
))

/**Serialize and deserialize users */
passport.serializeUser((user, done) => {
  done(null, user.user_id);
});

passport.deserializeUser(async (id, done) => {
  try {
      const query = 'SELECT user_id, username, email FROM users WHERE user_id = $1';
      const { rows } = await pool.query(query, [id]);

      if (rows.length === 0) {
          return done(new Error('User not found'), null);
      }

      const user = rows[0];
      done(null, user);
  } catch (err) {
      done(err, null);
  }
});

/**Logging users */
app.post('/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
      if (err) {
          console.error(err);
          return next(err);
      }
      if (!user) {
          /**if authentication fails */
          return res.status(400).json({ message: info.message || 'Login failed' });
      }
      /**Logging */
      req.logIn(user, (err) => {
          if (err) {
              console.error(err);
              return next(err);
          }
          /**Successful login */
          return res.json({ message: 'Login successful', user: { user_id: user.user_id, username: user.username, email: user.email } });
      });
  })(req, res, next);
});

/** Logout User */
app.get('/logout', (req, res, next) => {
  req.logout(function(err) {
      if (err) { return next(err); }
      res.json({ message: 'Logged out successfully' });
  });
});

/**Middleware to protect routes */
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
      return next();
  }
  res.status(401).json({ message: 'Unauthorized: Please log in to access this resource.' });
}


/**Getting the profile for a certain user*/
app.get('/user/:user_id', ensureAuthenticated, async (req, res, next) => {
  const { user_id } = req.params;

  try {
    /** Convert user_id to integer and compare with logged-in user's ID*/
    const requestedUserId = parseInt(user_id, 10);
    if (requestedUserId !== req.user.user_id) {
      return res.status(403).json({ message: 'Forbidden: You can only access your own user data.' });
    }

    /** Query to fetch user details, their purchased products, and products in their cart*/
    const query = `
      SELECT 
        'sale' as type,
        u.user_id, 
        u.username, 
        u.email,
        s.product_id,
        s.quantity as quantity,
        s.sale_date,
        s.total_price,
        p.product_name,
        p.price
      FROM 
        users u
      LEFT JOIN 
        sales s ON u.user_id = s.user_id
      LEFT JOIN 
        products p ON s.product_id = p.product_id
      WHERE 
        u.user_id = $1
      UNION ALL
      SELECT
        'cart' as type,
        u.user_id,
        u.username, 
        u.email,
        c.product_id,
        c.quantity as quantity,
        NULL as sale_date,  /* Cart items do not have a sale date */
        NULL as total_price, /* Cart items do not have a total price yet */
        p.product_name,
        p.price
      FROM
        users u
      LEFT JOIN
        carts c ON u.user_id = c.user_id
      LEFT JOIN
        products p ON c.product_id = p.product_id
      WHERE
        u.user_id = $1 AND c.status = 'active'  /* Assuming you want active cart items */
      ORDER BY
        type, sale_date DESC
    `;
    const { rows } = await pool.query(query, [requestedUserId]);

    if (rows.length === 0) {
      return res.status(404).json({ message: 'User not found.' });
    }

    // Structure the response
    const user = {
      user_id: rows[0].user_id,
      username: rows[0].username,
      email: rows[0].email,
      sales: [],
      cart: []
    };

    rows.forEach(row => {
      if (row.type === 'sale') {
        user.sales.push({
          product_id: row.product_id,
          name: row.product_name,
          price: row.price,
          sale_date: row.sale_date,
          quantity: row.quantity,
          total_price: row.total_price
        });
      } else if (row.type === 'cart') {
        user.cart.push({
          product_id: row.product_id,
          name: row.product_name,
          price: row.price,
          quantity: row.quantity
        });
      }
    });

    res.json({ user });
  } catch (error) {
    console.error("Error:", error.message);
    res.status(500).json({ message: 'Internal Server Error.' });
  }
});



/**Listening on server */
const server = app.listen(port, () => {
    console.log(`Listening to port ${port} for the project number 4`);
});

process.on('SIGTERM', () => {
    console.log('SIGTERM signal received: closing HTTP server');
    server.close(() => {
        console.log('HTTP server closed');
        pool.end(() => {
            console.log('Pool has ended');
        })
    })
})