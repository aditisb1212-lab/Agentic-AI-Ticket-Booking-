import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { initDatabase, query, get, run } from 'database.js';
import { handleAgentChat } from 'aiservice.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'JWT_SECRET';

app.use(cors());
app.use(express.json());

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    req.user = null;
    return next();
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      req.user = null;
      return next();
    }
    req.user = user;
    next();
  });
};

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const existingUser = await get('SELECT id FROM users WHERE email = ?', [email]);
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    const result = await run(`
      INSERT INTO users (name, email, password_hash, role)
      VALUES (?, ?, ?, 'user')
    `, [name, email, passwordHash]);

    const userId = result.insertId;
    const token = jwt.sign({ id: userId, name, email }, JWT_SECRET, { expiresIn: '24h' });

    res.status(201).json({
      token,
      user: { id: userId, name, email, role: 'user' }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await get('SELECT * FROM users WHERE email = ?', [email]);
    if (!user) {
      return res.status(400).json({ error: 'Invalid email or password' });
    }

    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign({ id: user.id, name: user.name, email: user.email }, JWT_SECRET, { expiresIn: '24h' });

    res.json({
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/api/events', async (req, res) => {
  try {
    const events = await query('SELECT * FROM events');
    res.json(events);
  } catch (error) {
    console.error('Error fetching events:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/api/events/:id', async (req, res) => {
  try {
    const eventId = req.params.id;
    const event = await get('SELECT * FROM events WHERE id = ?', [eventId]);
    if (!event) {
      return res.status(404).json({ error: 'Event not found' });
    }

    const seats = await query('SELECT id, seat_number, status, user_id FROM seats WHERE event_id = ?', [eventId]);
    res.json({ event, seats });
  } catch (error) {
    console.error('Error fetching event details:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.post('/api/bookings', authenticateToken, async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized. Please sign in.' });
    }

    const { eventId, seats } = req.body;
    if (!eventId || !seats || !Array.isArray(seats) || seats.length === 0) {
      return res.status(400).json({ error: 'Event ID and seat selections are required' });
    }

    const event = await get('SELECT price, title FROM events WHERE id = ?', [eventId]);
    if (!event) {
      return res.status(404).json({ error: 'Event not found' });
    }

    const placeholders = seats.map(() => '?').join(',');
    const unavailableSeats = await query(`
      SELECT seat_number FROM seats 
      WHERE event_id = ? AND seat_number IN (${placeholders}) AND status != 'available'
    `, [eventId, ...seats]);

    if (unavailableSeats.length > 0) {
      const seatNames = unavailableSeats.map(s => s.seat_number).join(', ');
      return res.status(400).json({ error: `Seat(s) ${seatNames} are no longer available.` });
    }

    const totalPrice = parseFloat(event.price) * seats.length;
    const seatsString = seats.join(', ');

    const bookingRes = await run(`
      INSERT INTO bookings (user_id, event_id, total_price, seats_booked, status)
      VALUES (?, ?, ?, ?, 'confirmed')
    `, [req.user.id, eventId, totalPrice, seatsString]);

    const bookingId = bookingRes.insertId;

    for (const seat of seats) {
      await run(`
        UPDATE seats 
        SET status = 'booked', user_id = ?, booking_id = ? 
        WHERE event_id = ? AND seat_number = ?
      `, [req.user.id, bookingId, eventId, seat]);
    }

    res.status(201).json({
      success: true,
      bookingId,
      totalPrice,
      seatsBooked: seats,
      message: 'Tickets booked successfully!'
    });
  } catch (error) {
    console.error('Booking error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/api/bookings/user/:userId', authenticateToken, async (req, res) => {
  try {
    if (!req.user || req.user.id !== parseInt(req.params.userId)) {
      return res.status(401).json({ error: 'Unauthorized access' });
    }

    const bookings = await query(`
      SELECT b.*, e.title, e.event_date, e.event_time, e.venue, e.image_url 
      FROM bookings b
      JOIN events e ON b.event_id = e.id
      WHERE b.user_id = ?
      ORDER BY b.booking_date DESC
    `, [req.user.id]);

    res.json(bookings);
  } catch (error) {
    console.error('Error fetching user bookings:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.post('/api/bookings/:id/cancel', authenticateToken, async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const bookingId = req.params.id;
    const booking = await get('SELECT * FROM bookings WHERE id = ? AND user_id = ?', [bookingId, req.user.id]);
    
    if (!booking) {
      return res.status(404).json({ error: 'Booking not found' });
    }

    if (booking.status === 'cancelled') {
      return res.status(400).json({ error: 'Booking is already cancelled' });
    }

    await run('UPDATE bookings SET status = "cancelled" WHERE id = ?', [bookingId]);
    await run(`
      UPDATE seats 
      SET status = "available", user_id = NULL, booking_id = NULL 
      WHERE booking_id = ?
    `, [bookingId]);

    res.json({ success: true, message: 'Booking cancelled successfully' });
  } catch (error) {
    console.error('Cancellation error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.post('/api/agent/chat', authenticateToken, async (req, res) => {
  try {
    const { message } = req.body;
    if (!message) {
      return res.status(400).json({ error: 'Message content is required' });
    }

    const userId = req.user ? req.user.id : null;
    const userEmail = req.user ? req.user.email : null;

    const agentResponse = await handleAgentChat(message, userId, userEmail);
    res.json(agentResponse);
  } catch (error) {
    console.error('Agent chat error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

const startServer = async () => {
  try {
    await initDatabase();
    app.listen(PORT, () => {
      console.log(`🚀 [Server] Ticket Booking REST API running at http://localhost:${PORT}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
};

startServer();
