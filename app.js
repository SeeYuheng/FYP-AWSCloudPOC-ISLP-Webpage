const express = require('express'); 
const mysql = require('mysql2');
const multer = require('multer'); 
const app = express();

// Set up multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'public/images'); // Directory to save uploaded files
  },
  filename: (req, file, cb) => {
    cb(null, file.originalname);
  }
});

const upload = multer({ storage: storage });

// Create MySQL connection 
const connection = mysql.createConnection({ 
  host: 'localhost', 
  user: 'root', 
  password: '', 
  database: 'erdforfyp' 
});
 
connection.connect((err) => { 
  if (err) { 
    console.error('Error connecting to MySQL:', err); 
    return; 
  } 
  console.log('Connected to MySQL database'); 
});
 
// Set up view engine 
app.set('view engine', 'ejs'); 

// enable static files 
app.use(express.static('public'));

// enable form processing
app.use(express.urlencoded({
  extended: false
}));

// enable static files
app.use(express.static('public'));

// Define routes
app.get('/login', (req, res) => {
  connection.query('SELECT * FROM account', (error, results) => {
    if (error) throw error;
    res.render('login', { account: results }); // Render HTML page with data
  });
});

app.get('/lecturer', (req, res) => { 
  connection.query('SELECT * FROM project', (error, results) => { 
    if (error) throw error; 
    res.render('lecturer', { project: results }); // Render HTML page with data 
  }); 
});

// Search Bar
app.get('/search', (req, res) => {
  const query = req.query.query;
  connection.query('SELECT * FROM project WHERE project_title LIKE ?', [`%${query}%`], (error, searchResults) => {
    if (error) {
      console.error('Database query error:', error.message);
      return res.status(500).send('Error searching for ISLP');
    }
    res.render('searchResults', { query, results: searchResults });
  });
});

app.get('/ISLP/:projectid', (req, res) => {
  const projectid = req.params.projectid;
  const sql = 'SELECT * FROM project WHERE projectid = ?';

  connection.query(sql, [projectid], (error, results) => {
    if (error) {
      console.error('Database query error:', error.message);
      return res.status(500).send('Error retrieving project by ID');
    }

    if (results.length > 0) {
      res.render('ISLP', { project: results[0] });
    } else {
      res.status(404).send('Project not found');
    }
  });
});

app.get('/addISLP', (req, res) => {
  res.render('addISLP');
});

app.post('/addISLP', (req, res) => {
  // Extract project data from the request body
  const { project_title, project_head, description, project_start, project_end} = req.body;
  const sql = 'INSERT INTO project (project_title, project_head, description, project_start, project_end) VALUES (?, ?, ?, ?, ?)';
  connection.query(sql, [project_title, project_head, description, project_start, project_end], (error, results) => {
    if (error) {
      console.error("Error adding project:", error);
      res.status(500).send('Error adding project');
    } else {
      res.redirect('/lecturer');
    }
  });
});

app.get('/editISLP/:projectid', (req, res) => {
  const projectid = req.params.projectid;
  const sql = 'SELECT * FROM project WHERE projectid = ?';
  // Fetch data from MySQL based on the project ID
  connection.query(sql, [projectid], (error, results) => {
    if (error) {
      console.error('Database query error:', error.message);
      return res.status(500).send('Error Retrieving ticket by ID');
    }
    // Check if any product with the given ID was found
    if (results.length > 0) {
      // Render HTML page with the product data
      res.render('editISLP', { project: results[0] });
    } else {
      // If no product with the given ID was found, render a 404 page or handle it accordingly
      res.status(404).send('ISLP not found');
    }
  });
});

app.post('/editISLP/:projectid', (req, res) => {
  const projectid = req.params.projectid;

  // Destructure data from request body
  let {
    project_title,
    project_head,
    description,
    project_start,
    project_end
  } = req.body;

  // Build dynamic updateFields
  let updateFields = {
    project_title,
    project_head,
    description,
    project_start,
    project_end
  };

  // Prepare fields and values for the SQL query
  const fields = Object.keys(updateFields);
  const values = Object.values(updateFields);

  // Dynamically generate SQL SET clause
  const sql = `UPDATE project SET ${fields.map(field => `${field} = ?`).join(', ')} WHERE projectid = ?`;

  // Add projectid to the end of the values array
  values.push(projectid);

  // Execute the query
  connection.query(sql, values, (error, results) => {
    if (error) {
      console.error("Error updating ISLP project:", error);
      return res.status(500).send("Error updating ISLP project.");
    } else {
      res.redirect('/lecturer');
    }
  });
});


app.get('/deleteISLP/:projectid', (req, res) => {
  const projectid = req.params.projectid;
  const sql = 'DELETE FROM project WHERE projectid = ?';
  connection.query(sql, [projectid], (error, results) => {
    if (error) {
      // Handle any errors that occur during the database operation
      console.error('Database query error:', error.message);
      return res.status(500).send('Error deleting project by ID');
    } else {
      // Send a success response
      res.redirect('/lecturer');
    }
  });
});

app.get('/contact', (req, res) => {
  res.render('contact');
});

app.post('/submit', (req, res) => {
  // Activity 3: Edit the lines below include the additional form fields sent by the form
  let { name, email, contact_no, comments } = req.body;
  const sql = 'INSERT INTO feedback (name, email, contact_no, comments) VALUES (?, ?, ?, ?)';
  connection.query(sql, [name, email, contact_no, comments], (error, results) => {
    if (error) {
      console.error("Error adding feedback:", error);
      return res.status(500).send('Error adding feedback');
    } else {
      res.render('submit', { name, email, contact_no, comments });
    }
  });
});

app.get('/feedback', (req, res) => { 
  connection.query('SELECT * FROM feedback', (error, results) => { 
    if (error) throw error; 
    res.render('feedback', { feedback: results }); // Render HTML page with data 
  }); 
}); 

const PORT = process.env.PORT || 3000; 
app.listen(PORT, () => console.log(`Server running http://localhost:${PORT}/lecturer`));

// Tan Ye Kai 23024918
