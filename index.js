require('dotenv').config();
const express = require('express');
const pool = require('./db');
const bcrypt = require('bcrypt');

/** Import passport for logging in */
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session');

const app = express();
const port = process.env.PORT || 3000;

/** Validate Essential Environment Variables */
const requiredEnv = ['SESSION_SECRET', 'NODE_ENV'];
const missingEnv = requiredEnv.filter(env => !process.env[env]);

if (missingEnv.length > 0) {
  console.error(`Missing required environment variables: ${missingEnv.join(', ')}`);
  process.exit(1);
}

/** Middleware to parse JSON bodies */
app.use(express.json()); // For parsing application/json
app.use(express.urlencoded({ extended: true })); // For parsing application/x-www-form-urlencoded

/** Express session middleware */
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production', // Simplified expression
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 24 // One day
  }
}));

/** Initialize passport */
app.use(passport.initialize());
app.use(passport.session());

app.get('/', (req, res) => {
  res.send('Testing the fourth project');
});

/** Getting all the users */
app.get('/users', async (req, res) => {
  try {
    const result = await pool.query('SELECT username FROM users');
    res.json({
      success: true,
      data: result.rows
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});

/** Registering new users */
app.post('/register', async (req, res) => {
  try {
    /** Registering new user - they must provide username, email, password */
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ success: false, message: 'All fields are required' });
    }

    /** Check if the username or email already exists */
    const existingUserQuery = 'SELECT 1 FROM users WHERE username = $1 OR email = $2';
    const existingUserResult = await pool.query(existingUserQuery, [username, email]);
    if (existingUserResult.rows.length > 0) {
      return res.status(400).json({ success: false, message: 'Either username or email already exists' });
    }

    /** Check if the email is valid */
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ success: false, message: 'Invalid email format' });
    }

    /** Hash the password */
    const saltRounds = 9;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    /** Insert the new user into the database */
    const insertUserQuery = `
      INSERT INTO users(username, password, email)
      VALUES ($1, $2, $3) RETURNING user_id, username, email
    `;
    const result = await pool.query(insertUserQuery, [username, hashedPassword, email]);

    /** Show the data excluding the password */
    const newUser = result.rows[0];
    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      data: {
        user_id: newUser.user_id,
        username: newUser.username,
        email: newUser.email,
      }
    });
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});

/** Configure Passport Local Strategy */
passport.use(new LocalStrategy(
  async (username, password, done) => {
    try {
      const query = 'SELECT * FROM users WHERE username = $1';
      const { rows } = await pool.query(query, [username]);
      if (rows.length === 0) {
        return done(null, false, { message: 'Incorrect username.' });
      }

      const user = rows[0];

      // Check if the password matches
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return done(null, false, { message: 'Incorrect password.' });
      }

      // Remove password from user object before proceeding
      delete user.password;

      // Successful authentication
      return done(null, user);

    } catch (err) {
      return done(err);
    }
  }
));

/** Serialize and deserialize users */
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

/** Logging in users */
app.post('/login', async (req, res, next) => {
  passport.authenticate('local', async (err, user, info) => {
    if (err) {
      console.error(err);
      return next(err);
    }
    if (!user) {
      return res.status(400).json({ success: false, message: info.message || 'Login failed' });
    }
    try {
      // Promisify req.logIn
      await new Promise((resolve, reject) => {
        req.logIn(user, (err) => {
          if (err) return reject(err);
          resolve();
        });
      });
      // Send only necessary user information
      return res.json({
        success: true,
        message: 'Login successful',
        data: {
          user_id: user.user_id,
          username: user.username,
          email: user.email
        }
      });
    } catch (err) {
      console.error(err);
      return next(err);
    }
  })(req, res, next);
});

/** Logout User */
app.get('/logout', (req, res, next) => {
  req.logout(function(err) {
    if (err) { 
      console.error(err);
      return next(err); 
    }
    res.json({ success: true, message: 'Logged out successfully' });
  });
});

/** Middleware to protect routes */
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ success: false, message: 'Unauthorized: Please log in to access this resource.' });
}

/** Getting the profile for a certain user */
app.get('/user/:user_id', ensureAuthenticated, async (req, res, next) => {
  const { user_id } = req.params;

  try {
    /** Convert user_id to integer and compare with logged-in user's ID */
    const requestedUserId = parseInt(user_id, 10);
    if (isNaN(requestedUserId)) {
      return res.status(400).json({ success: false, message: 'Invalid user ID.' });
    }
    if (requestedUserId !== req.user.user_id) {
      return res.status(403).json({ success: false, message: 'Forbidden: You can only access your own user data.' });
    }

    /** Corrected SQL Query: Retain carts instead of deleting them */
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
        ci.product_id,
        ci.quantity as quantity,
        NULL as sale_date,
        ci.total_price,
        p.product_name,
        p.price
      FROM
        users u
      JOIN
        carts c ON u.user_id = c.user_id
      JOIN
        cart_items ci ON c.cart_id = ci.cart_id
      JOIN
        products p ON ci.product_id = p.product_id
      WHERE
        u.user_id = $1 AND c.status = 'active'
      ORDER BY
        type, sale_date DESC
    `;
    const { rows } = await pool.query(query, [requestedUserId]);

    if (rows.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found.' });
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
          quantity: row.quantity,
          total_price: row.total_price
        });
      }
    });

    res.json({ success: true, data: { user } });
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});

/** Get all the products of a certain category */
app.get('/products', async (req, res) => { // Refactored to use async/await
  const categoryId = req.query.category;

  if (!categoryId) {
    return res.status(400).json({ success: false, error: 'Category ID is required. Example: /products?category=1' });
  }

  try {
    const query = 'SELECT * FROM products WHERE category_id = $1';
    const results = await pool.query(query, [categoryId]);
    res.json({ success: true, data: results.rows });
  } catch (error) {
    console.error('Error fetching products:', error);
    res.status(500).json({ success: false, error: 'Database query failed' });
  }
});

/** Get a certain product */
app.get('/products/:productId', async (req, res) => { // Refactored to use async/await
  const productId = req.params.productId;

  try {
    const query = 'SELECT * FROM products WHERE product_id = $1';
    const results = await pool.query(query, [productId]);

    if (results.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Product not found' });
    }

    res.json({ success: true, data: results.rows[0] });
  } catch (error) {
    console.error('Error fetching product:', error);
    res.status(500).json({ success: false, error: 'Database query failed' });
  }
});

/** Buyer adds products to the cart */
app.post('/cart', ensureAuthenticated, async (req, res) => {
  const client = await pool.connect();

  try {
    const { product_id, quantity } = req.body;
    const user_id = req.user.user_id;

    // Validate Input
    if (!product_id || quantity === undefined) {
      return res.status(400).json({ success: false, message: 'Product ID and quantity are required.' });
    }

    const parsedQuantity = parseInt(quantity, 10);
    if (isNaN(parsedQuantity) || parsedQuantity < 1) {
      return res.status(400).json({ success: false, message: 'Quantity must be a positive integer.' });
    }

    // Start Transaction
    await client.query('BEGIN');

    // Check for Existing Active Cart
    const checkCartQuery = `
      SELECT cart_id
      FROM carts
      WHERE user_id = $1 AND status = 'active'
      LIMIT 1
    `;
    const cartResult = await client.query(checkCartQuery, [user_id]);

    let cart_id;
    if (cartResult.rows.length > 0) {
      cart_id = cartResult.rows[0].cart_id;
    } else {
      // Create a new cart
      const createCartQuery = `
        INSERT INTO carts (user_id)
        VALUES ($1)
        RETURNING cart_id
      `;
      const newCartResult = await client.query(createCartQuery, [user_id]);
      cart_id = newCartResult.rows[0].cart_id;
    }

    // Calculate total_price
    const productPriceQuery = 'SELECT price FROM products WHERE product_id = $1';
    const productPriceResult = await client.query(productPriceQuery, [product_id]);
    if (productPriceResult.rows.length === 0) {
      throw new Error('Product not found.');
    }
    const productPrice = productPriceResult.rows[0].price;
    const total_price = productPrice * parsedQuantity;

    // Insert Cart Item with total_price
    const insertCartItemQuery = `
      INSERT INTO cart_items (product_id, quantity, cart_id, total_price)
      VALUES ($1, $2, $3, $4)
      RETURNING cart_item_id, product_id, quantity, total_price
    `;
    const cartItemResult = await client.query(insertCartItemQuery, [product_id, parsedQuantity, cart_id, total_price]);
    const newCartItem = cartItemResult.rows[0];

    // Commit Transaction
    await client.query('COMMIT');

    // Fetch Detailed Information (Optional)
    const fetchDetailsQuery = `
      SELECT 
        ci.cart_item_id,
        c.cart_id,
        u.username,
        p.product_name,
        ci.quantity,
        ci.total_price
      FROM cart_items ci
      JOIN carts c ON ci.cart_id = c.cart_id
      JOIN users u ON c.user_id = u.user_id
      JOIN products p ON ci.product_id = p.product_id
      WHERE ci.cart_item_id = $1
    `;
    const detailsResult = await client.query(fetchDetailsQuery, [newCartItem.cart_item_id]);
    const detailedCartItem = detailsResult.rows[0];

    // Send Response
    res.status(201).json({
      success: true,
      message: 'Product added to cart successfully',
      data: {
        cart_item: {
          cart_item_id: detailedCartItem.cart_item_id,
          cart_id: detailedCartItem.cart_id,
          username: detailedCartItem.username,
          product_name: detailedCartItem.product_name,
          quantity: detailedCartItem.quantity,
          total_price: detailedCartItem.total_price
        }
      }
    });

  } catch (error) {
    // Rollback Transaction in Case of Error
    await client.query('ROLLBACK');
    console.error("Error:", error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  } finally {
    client.release();
  }
});

/** Add product to a specific cart */
app.post('/cart/:cart_id', ensureAuthenticated, async (req, res) => {
  const client = await pool.connect();

  try {
    const { product_id, quantity } = req.body;
    const user_id = req.user.user_id;
    const { cart_id } = req.params;  // Extract cart_id from URL parameters

    // Validate Input
    if (!product_id || quantity === undefined) {
      return res.status(400).json({ success: false, message: 'Product ID and quantity are required.' });
    }

    const parsedQuantity = parseInt(quantity, 10);
    if (isNaN(parsedQuantity) || parsedQuantity < 1) {
      return res.status(400).json({ success: false, message: 'Quantity must be a positive integer.' });
    }

    // Start Transaction
    await client.query('BEGIN');

    // Check if the cart belongs to the user
    const checkCartQuery = `
      SELECT cart_id
      FROM carts
      WHERE cart_id = $1 AND user_id = $2 AND status = 'active'
      LIMIT 1
    `;
    const cartResult = await client.query(checkCartQuery, [cart_id, user_id]);

    if (cartResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ success: false, message: 'Active cart not found for the user.' });
    }

    // Calculate total_price
    const productPriceQuery = 'SELECT price FROM products WHERE product_id = $1';
    const productPriceResult = await client.query(productPriceQuery, [product_id]);
    if (productPriceResult.rows.length === 0) {
      throw new Error('Product not found.');
    }
    const productPrice = productPriceResult.rows[0].price;
    const total_price = productPrice * parsedQuantity;

    // Insert Cart Item with total_price
    const insertCartItemQuery = `
      INSERT INTO cart_items (product_id, quantity, cart_id, total_price)
      VALUES ($1, $2, $3, $4)
      RETURNING cart_item_id, product_id, quantity, total_price
    `;
    const cartItemResult = await client.query(insertCartItemQuery, [product_id, parsedQuantity, cart_id, total_price]);
    const newCartItem = cartItemResult.rows[0];

    // Commit Transaction
    await client.query('COMMIT');

    // Fetch Detailed Information (Optional)
    const fetchDetailsQuery = `
      SELECT 
        ci.cart_item_id,
        c.cart_id,
        u.username,
        p.product_name,
        ci.quantity,
        ci.total_price
      FROM cart_items ci
      JOIN carts c ON ci.cart_id = c.cart_id
      JOIN users u ON c.user_id = u.user_id
      JOIN products p ON ci.product_id = p.product_id
      WHERE ci.cart_item_id = $1
    `;
    const detailsResult = await client.query(fetchDetailsQuery, [newCartItem.cart_item_id]);
    const detailedCartItem = detailsResult.rows[0];

    // Send Response
    res.status(201).json({
      success: true,
      message: 'Product added to cart successfully',
      data: {
        cart_item: {
          cart_item_id: detailedCartItem.cart_item_id,
          cart_id: detailedCartItem.cart_id,
          username: detailedCartItem.username,
          product_name: detailedCartItem.product_name,
          quantity: detailedCartItem.quantity,
          total_price: detailedCartItem.total_price
        }
      }
    });

  } catch (error) {
    // Rollback Transaction in Case of Error
    await client.query('ROLLBACK');
    console.error("Error:", error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  } finally {
    client.release();
  }
});

/** Get cart details with ownership verification */
app.get('/cart/:cart_id', ensureAuthenticated, async (req, res) => {
  const client = await pool.connect();
  const { cart_id } = req.params; // Extract cart_id from the URL parameter

  try {
    /** Verify that the cart belongs to the authenticated user */
    const verifyCartQuery = `
      SELECT ci.cart_item_id, c.cart_id, u.username, p.product_name, ci.quantity, ci.total_price
      FROM cart_items ci
      JOIN carts c ON ci.cart_id = c.cart_id
      JOIN users u ON c.user_id = u.user_id
      JOIN products p ON ci.product_id = p.product_id
      WHERE c.cart_id = $1 AND c.user_id = $2
    `;
    const cartResult = await client.query(verifyCartQuery, [cart_id, req.user.user_id]);

    if (cartResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Cart not found or access denied.' });
    }

    res.status(200).json({ success: true, data: { cart_items: cartResult.rows } });
  } catch (error) {
    console.error('Error fetching cart:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  } finally {
    client.release();
  }
});

/** Checkout a cart */
app.post('/cart/:cart_id/checkout', ensureAuthenticated, async (req, res) => {
  const client = await pool.connect();
  const { cart_id } = req.params; // Extract cart_id from URL parameters
  const user_id = req.user.user_id;

  try {
    // Start Transaction
    await client.query('BEGIN');

    // 1. Validate the Cart
    const cartQuery = `
      SELECT c.cart_id, c.user_id, c.status, ci.cart_item_id, ci.product_id, ci.quantity, ci.total_price
      FROM carts c
      JOIN cart_items ci ON c.cart_id = ci.cart_id
      WHERE c.cart_id = $1 AND c.status = 'active' FOR UPDATE
    `;
    const cartResult = await client.query(cartQuery, [cart_id]);

    if (cartResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ success: false, message: 'Active cart not found.' });
    }

    const cart = {
      cart_id: cartResult.rows[0].cart_id,
      user_id: cartResult.rows[0].user_id,
      status: cartResult.rows[0].status,
      items: cartResult.rows.map(row => ({
        cart_item_id: row.cart_item_id,
        product_id: row.product_id,
        quantity: row.quantity,
        total_price: row.total_price,
      })),
    };

    // Check if the cart belongs to the authenticated user
    if (cart.user_id !== user_id) {
      await client.query('ROLLBACK');
      return res.status(403).json({ success: false, message: 'Unauthorized access to this cart.' });
    }

    // 2. Calculate Total Amount
    const totalAmount = cart.items.reduce((sum, item) => sum + parseFloat(item.total_price), 0);

    // 3. Create a Sale Record
    const saleInsertQuery = `
      INSERT INTO sales (user_id, cart_id, total_price, sale_date)
      VALUES ($1, $2, $3, NOW())
      RETURNING sale_id, sale_date
    `;
    const saleResult = await client.query(saleInsertQuery, [user_id, cart.cart_id, totalAmount]);

    const sale = saleResult.rows[0];

    // 4. Update Cart Status to 'checked_out'
    const updateCartStatusQuery = `
      UPDATE carts
      SET status = 'checked_out'
      WHERE cart_id = $1
    `;
    await client.query(updateCartStatusQuery, [cart.cart_id]);

    // Note: Removed deletion of cart items and cart to maintain referential integrity

    // Commit Transaction
    await client.query('COMMIT');

    // 5. Respond to the Client
    return res.status(200).json({
      success: true,
      message: 'Checkout successful.',
      data: {
        sale: {
          sale_id: sale.sale_id,
          sale_date: sale.sale_date,
          total_amount: totalAmount,
        },
      },
    });
  } catch (error) {
    // Rollback Transaction in Case of Error
    await client.query('ROLLBACK');
    console.error('Checkout Error:', error);
    return res.status(500).json({ success: false, message: 'An error occurred during checkout.' });
  }
});


/** Get Sales for a Specific User */
app.get('/sales/:user_id', ensureAuthenticated, async (req, res) => {
  const client = await pool.connect();
  const { user_id } = req.params;

  try {
    // Convert and validate user_id
    const requestedUserId = parseInt(user_id, 10);
    if (isNaN(requestedUserId)) {
      return res.status(400).json({ success: false, message: 'Invalid user ID.' });
    }

    // Authorization: User can only access their own sales
    if (requestedUserId !== req.user.user_id) {
      return res.status(403).json({ success: false, message: 'Forbidden: You can only access your own sales data.' });
    }

    /** Fetch Sales */
    const salesQuery = `
      SELECT 
        s.sale_id,
        s.sale_date,
        s.total_price,
        s.cart_id
      FROM 
        sales s
      WHERE 
        s.user_id = $1
      ORDER BY 
        s.sale_date DESC, s.sale_id DESC
    `;
    const salesResult = await client.query(salesQuery, [requestedUserId]);

    if (salesResult.rows.length === 0) {
      return res.status(200).json({ success: true, message: 'No sales found for this user.', data: { sales: [] } });
    }

    /** Fetch Sale Items for Each Sale */
    const sales = await Promise.all(salesResult.rows.map(async (sale) => {
      const saleItemsQuery = `
        SELECT 
          ci.cart_item_id,
          p.product_name,
          ci.quantity,
          ci.total_price
        FROM 
          cart_items ci
        JOIN 
          products p ON ci.product_id = p.product_id
        WHERE 
          ci.cart_id = $1
      `;
      const itemsResult = await client.query(saleItemsQuery, [sale.cart_id]);

      return {
        sale_id: sale.sale_id,
        sale_date: sale.sale_date,
        total_price: sale.total_price,
        items: itemsResult.rows.map(item => ({
          cart_item_id: item.cart_item_id,
          product_name: item.product_name,
          quantity: item.quantity,
          total_price: item.total_price
        }))
      };
    }));

    /** Send the Response */
    res.status(200).json({
      success: true,
      data: {
        sales
      }
    });

  } catch (error) {
    console.error('Error fetching sales:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  } finally {
    client.release();
  }
});


/** Listening on server */
const server = app.listen(port, () => {
  console.log(`Listening to port ${port} for the project number 4`);
});

/** Graceful Shutdown Handling for Multiple Signals */
const shutdown = () => {
  console.log('Shutdown signal received: closing HTTP server');
  server.close(() => {
    console.log('HTTP server closed');
    pool.end(() => {
      console.log('Database pool has ended');
      process.exit(0);
    });
  });
};

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
