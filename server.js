const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const pool = new Pool({
    user: 'oss_admin',
    host: '148.72.246.179',
    database: 'syoft',
    password: 'Latitude77',
    schema: "public",
    port: '5432',
  });

const SECRET_KEY = 'shiva143'; 

app.use(bodyParser.json());

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

app.post('/register', async (req, res) => {
    const { username, email, password, role } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query('INSERT INTO users (username, email, password, role) VALUES ($1, $2, $3, $4) RETURNING id', [username, email, hashedPassword, role]);
        res.status(201).json({ message: 'User created', id: result.rows[0].id });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});


app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = result.rows[0];
        
        if (user && await bcrypt.compare(password, user.password)) {
            const token = jwt.sign({ userId: user.id, role: user.role }, SECRET_KEY, { expiresIn: '1h' });
            res.json({ token });
        } else {
            res.status(401).json({ message: 'Invalid credentials' });
        }
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});


app.post('/products', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });

    const { title, description, inventory_count } = req.body;
    try {
        await pool.query('INSERT INTO products (title, description, inventory_count) VALUES ($1, $2, $3)', [title, description, inventory_count]);
        res.status(201).json({ message: 'Product created' });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});


app.get('/products', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin' && req.user.role !== 'manager') return res.status(403).json({ message: 'Forbidden' });

    try {
        const result = await pool.query('SELECT * FROM products');
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});


app.put('/products/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin' && req.user.role !== 'manager') return res.status(403).json({ message: 'Forbidden' });

    const { id } = req.params;
    const { title, description, inventory_count } = req.body;
    try {
        await pool.query('UPDATE products SET title = $1, description = $2, inventory_count = $3 WHERE id = $4', [title, description, inventory_count, id]);
        res.json({ message: 'Product updated' });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});


app.delete('/products/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });

    const { id } = req.params;
    try {
        await pool.query('DELETE FROM products WHERE id = $1', [id]);
        res.json({ message: 'Product deleted' });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
