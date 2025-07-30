const express = require('express'); 
const mysql = require('mysql2');
const multer = require('multer'); 
const session = require('express-session');
const flash = require('connect-flash');
const crypto = require('crypto');
const app = express();

// Password hashing functions using Node.js built-in crypto
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, hashedPassword) {
  const [salt, hash] = hashedPassword.split(':');
  const verifyHash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
  return hash === verifyHash;
}

// Set up multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'public/images');
  },
  filename: (req, file, cb) => {
    cb(null, file.originalname);
  }
});
const upload = multer({ storage: storage });

// MySQL connection 
const connection = mysql.createConnection({ 
  host: 'localhost', 
  user: 'root', 
  password: '', 
  database: 'fyp' 
});
 
connection.connect((err) => { 
  if (err) { 
    console.error('Error connecting to MySQL:', err); 
    return; 
  } 
  console.log('Connected to MySQL database'); 
});

// View engine and middleware
app.set('view engine', 'ejs'); 
app.use(express.static('public'));
app.use(express.urlencoded({ extended: false }));

// Session and flash
app.use(session({
  secret: 'secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { maxAge: 1000 * 60 * 60 * 24 }
}));
app.use(flash());

// Auth middleware
const checkAuthenticated = (req, res, next) => {
  if (req.session.user) return next();
  req.flash('error', 'Please log in to access this page');
  res.redirect('/login');
};

const checkRole = (...allowedRoles) => {
  return (req, res, next) => {
    if (req.session.user && allowedRoles.includes(req.session.user.roleid)) {
      return next();
    } else {
      req.flash('error', 'Access denied.');
      res.redirect('/login');
    }
  };
};

// Routes

app.get('/', (req, res) => {
  res.redirect('/login');
});

app.get('/login', (req, res) => {
  res.render('login', {
    errors: req.flash('error'),
    messages: req.flash('success')
  });
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    req.flash('error', 'All fields are required.');
    return res.redirect('/login');
  }

  const sql = 'SELECT * FROM account WHERE email = ?';
  connection.query(sql, [email], (err, results) => {
    if (err) {
      console.error('Login error:', err);
      return res.status(500).send('Server error during login');
    }

    if (results.length > 0) {
      const user = results[0];
      
      // Check if password is hashed (contains ':') or plain text
      let passwordMatch = false;
      if (user.password.includes(':')) {
        // Password is hashed, verify it
        passwordMatch = verifyPassword(password, user.password);
      } else {
        // Password is plain text (for backward compatibility)
        passwordMatch = (password === user.password);
        
        // If login successful with plain text, hash the password for security
        if (passwordMatch) {
          const hashedPassword = hashPassword(password);
          const updateSql = 'UPDATE account SET password = ? WHERE accountid = ?';
          connection.query(updateSql, [hashedPassword, user.accountid], (updateErr) => {
            if (updateErr) {
              console.error('Error updating password hash:', updateErr);
            }
          });
        }
      }

      if (passwordMatch) {
        req.session.user = user;

        // Redirect based on roleid
        if (user.roleid === 1) {
          return res.redirect('/admin');
        } else if (user.roleid === 2) {
          return res.redirect('/lecturer');
        } else if (user.roleid === 3) {
          return res.redirect('/student');
        } else {
          return res.redirect('/');
        }
      } else {
        req.flash('error', 'Invalid email or password.');
        res.redirect('/login');
      }
    } else {
      req.flash('error', 'Invalid email or password.');
      res.redirect('/login');
    }
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

app.get('/lecturer', checkAuthenticated, checkRole(2), (req, res) => { 
  const sql = `
    SELECT p.*, s.name as project_status 
    FROM project p 
    LEFT JOIN status s ON p.status_statusid = s.statusid
  `;
  connection.query(sql, (error, results) => { 
    if (error) throw error; 
    res.render('lecturer', { 
      project: results,
      currentUser: req.session.user 
    }); 
  }); 
});

app.get('/student', checkAuthenticated, checkRole(3), (req, res) => {
  const sql = `
    SELECT p.*, s.name as project_status,
           CASE 
             WHEN CURDATE() < p.project_start THEN 'Approved'
             WHEN CURDATE() BETWEEN p.project_start AND p.project_end THEN 'Ongoing'
             WHEN CURDATE() > p.project_end THEN 'Finished'
             ELSE s.name
           END as dynamic_status,
           CASE WHEN pm.accountid IS NOT NULL AND pm.status = 'approved' THEN 1 ELSE 0 END as is_member,
           pm.status as member_status,
           (SELECT COUNT(*) FROM project_members pm2 WHERE pm2.projectid = p.projectid AND pm2.status = 'approved') as member_count
    FROM project p 
    LEFT JOIN status s ON p.status_statusid = s.statusid
    LEFT JOIN project_members pm ON p.projectid = pm.projectid AND pm.accountid = ? AND pm.status = 'approved'
    WHERE (p.status_statusid != 1) OR (p.status_statusid = 1 AND pm.accountid IS NOT NULL AND pm.status = 'approved')
    ORDER BY p.projectid DESC
  `;
  
  connection.query(sql, [req.session.user.accountid], (error, results) => {
    if (error) {
      console.error('Error fetching projects:', error);
      return res.status(500).send('Error loading projects');
    }
    
    res.render('student', { 
      project: results,
      currentUser: req.session.user 
    }); 
  });
});

app.get('/admin', checkAuthenticated, checkRole(1), (req, res) => {
  const sql = `
    SELECT p.*, s.name as project_status 
    FROM project p 
    LEFT JOIN status s ON p.status_statusid = s.statusid
  `;
  connection.query(sql, (error, results) => { 
    if (error) throw error; 
    res.render('admin', { 
      project: results,
      currentUser: req.session.user 
    }); 
  }); 
});

app.get('/pending', checkAuthenticated, checkRole(1), (req, res) => {
  const sql = `
    SELECT p.*, s.name as project_status 
    FROM project p 
    LEFT JOIN status s ON p.status_statusid = s.statusid
  `;
  connection.query(sql, (error, results) => { 
    if (error) throw error; 
    res.render('pending', { 
      project: results,
      currentUser: req.session.user 
    }); 
  }); 
});

app.get('/search', checkAuthenticated, (req, res) => {
  const { query } = req.query;
  
  if (!query) {
    return res.redirect('back');
  }

  const searchSql = `
    SELECT p.*, s.name as project_status,
           CASE 
             WHEN CURDATE() < p.project_start THEN 'Approved'
             WHEN CURDATE() BETWEEN p.project_start AND p.project_end THEN 'Ongoing'
             WHEN CURDATE() > p.project_end THEN 'Finished'
             ELSE s.name
           END as dynamic_status,
           CASE WHEN pm.accountid IS NOT NULL AND pm.status = 'approved' THEN 1 ELSE 0 END as is_member
    FROM project p 
    LEFT JOIN status s ON p.status_statusid = s.statusid
    LEFT JOIN project_members pm ON p.projectid = pm.projectid AND pm.accountid = ? AND pm.status = 'approved'
    WHERE p.project_title LIKE ? OR p.description LIKE ?
    ORDER BY p.projectid DESC
  `;
  
  const searchTerm = `%${query}%`;
  
  connection.query(searchSql, [req.session.user.accountid, searchTerm, searchTerm], (error, results) => {
    if (error) {
      console.error('Error searching projects:', error);
      return res.status(500).send('Error searching projects');
    }
    
    res.render('searchResults', { 
      results: results,
      query: query,
      currentUser: req.session.user 
    });
  });
});

app.get('/ISLP/:projectid', checkAuthenticated, (req, res) => {
  const projectid = req.params.projectid;

  const projectSql = `
    SELECT p.*, s.name as project_status 
    FROM project p 
    LEFT JOIN status s ON p.status_statusid = s.statusid 
    WHERE p.projectid = ?
  `;

  const postSql = `
    SELECT sub.*, acc.username, acc.roleid as author_roleid,
           (SELECT COUNT(*) FROM post_likes pl WHERE pl.submissionsid = sub.submissionsid) as like_count,
           (SELECT COUNT(*) FROM post_likes pl WHERE pl.submissionsid = sub.submissionsid AND pl.accountid = ?) as user_liked
    FROM submissions sub 
    JOIN account acc ON sub.accountid = acc.accountid 
    WHERE sub.projectid = ? 
    ORDER BY sub.submission_date DESC
  `;

  // Updated members query to only show APPROVED members
  const membersSql = `
    SELECT pm.*, acc.username, acc.email, acc.roleid
    FROM project_members pm
    JOIN account acc ON pm.accountid = acc.accountid
    WHERE pm.projectid = ? AND pm.status = 'approved'
    ORDER BY acc.username
  `;

  connection.query(projectSql, [projectid], (err, projectResults) => {
    if (err || projectResults.length === 0) return res.status(500).send('Project not found');

    connection.query(postSql, [req.session.user.accountid, projectid], (err, postResults) => {
      if (err) return res.status(500).send('Error loading posts');
      
      connection.query(membersSql, [projectid], (err, memberResults) => {
        if (err) {
          console.error('Error loading members:', err);
          memberResults = []; // Continue without members if there's an error
        }
        
        // Get facilitator details - project_head now contains a single lecturer ID
        let facilitators = [];
        if (projectResults[0].project_head) {
          const lecturerId = projectResults[0].project_head;
          
          // Query database for facilitator details
          const facilitatorSql = `
            SELECT username, email, roleid
            FROM account
            WHERE accountid = ?
            ORDER BY username
          `;
          
          connection.query(facilitatorSql, [lecturerId], (facilitatorErr, facilitatorResults) => {
            if (!facilitatorErr && facilitatorResults.length > 0) {
              facilitators = facilitatorResults;
            } else {
              console.error('Error querying facilitator or facilitator not found:', facilitatorErr);
            }
            
            res.render('ISLP', { 
              project: projectResults[0], 
              posts: postResults, 
              members: memberResults,
              facilitators: facilitators,
              user: req.session.user 
            });
          });
          return; // Exit early since we're handling the response in the callback
        } else {
          console.log('No project_head data found');
        }
        
        res.render('ISLP', { 
          project: projectResults[0], 
          posts: postResults, 
          members: memberResults,
          facilitators: facilitators,
          user: req.session.user 
        });
      });
    });
  });
});



app.get('/addISLP', checkAuthenticated, checkRole(1, 2), (req, res) => {
  // Get lecturers for project head dropdown (role ID 2)
  const lecturersSql = 'SELECT accountid, username, email, roleid FROM account WHERE roleid = 2';
  // Get students for members dropdown (role ID 3)
  const studentsSql = 'SELECT accountid, username, email, roleid FROM account WHERE roleid = 3';
  // Get all status options
  const statusSql = 'SELECT statusid, name, description FROM status ORDER BY statusid';
  
  connection.query(lecturersSql, (lecturerError, lecturerResults) => {
    if (lecturerError) {
      console.error('Error fetching lecturers:', lecturerError);
      return res.status(500).send('Error fetching lecturers');
    }
    
    connection.query(studentsSql, (studentError, studentResults) => {
      if (studentError) {
        console.error('Error fetching students:', studentError);
        return res.status(500).send('Error fetching students');
      }
      
      connection.query(statusSql, (statusError, statusResults) => {
        if (statusError) {
          console.error('Error fetching status options:', statusError);
          return res.status(500).send('Error fetching status options');
        }
        
        res.render('addISLP', { 
          lecturers: lecturerResults,
          students: studentResults,
          statusOptions: statusResults,
          currentUser: req.session.user 
        });
      });
    });
  });
});

app.post('/addISLP', checkAuthenticated, checkRole(1, 2), upload.single('project_images'), (req, res) => {                         
  const { project_title, description, project_start, project_end, members, status_statusid } = req.body;
  const project_images = req.file ? req.file.filename : null; // Get uploaded image filename
  
  // Current user automatically becomes the project head - no validation needed
  
  // Parse members JSON string
  let membersList = [];
  if (members && members.trim() !== '') {
    try {
      membersList = JSON.parse(members);
    } catch (error) {
      console.error('Error parsing members:', error);
      return res.status(400).send('Invalid members data');
    }
  }
  
  // Use the selected status directly
  insertProjectWithMembers(project_title, req.session.user.accountid, description, project_start, project_end, status_statusid, project_images, membersList, res, req.session.user);
});

// Helper function to insert project and members
function insertProjectWithMembers(project_title, project_head, description, project_start, project_end, statusId, project_images, membersList, res, user) {
  const sql = 'INSERT INTO project (project_title, project_head, description, project_start, project_end, status_statusid, project_images) VALUES (?, ?, ?, ?, ?, ?, ?)';
  connection.query(sql, [project_title, project_head, description, project_start, project_end, statusId, project_images], (error, results) => {
    if (error) {
      console.error('Error adding project:', error);
      return res.status(500).send('Error adding project: ' + error.message);
    }
    
    const projectId = results.insertId;
    console.log('Project added successfully with ID:', projectId);
    
    // Insert members if any
    if (membersList && membersList.length > 0) {
      insertProjectMembers(projectId, membersList, res, user);
    } else {
      console.log('No members to add');
      const redirectPath = user.roleid === 1 ? '/admin' : '/lecturer';
      res.redirect(redirectPath);
    }
  });
}

// Helper function to insert project members
function insertProjectMembers(projectId, membersList, res, user) {
  // Create project_members table if it doesn't exist
  const createTableSql = `
    CREATE TABLE IF NOT EXISTS project_members (
      id INT AUTO_INCREMENT PRIMARY KEY,
      projectid INT NOT NULL,
      accountid INT NOT NULL,
      added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (projectid) REFERENCES project(projectid) ON DELETE CASCADE,
      FOREIGN KEY (accountid) REFERENCES account(accountid) ON DELETE CASCADE,
      UNIQUE KEY unique_project_member (projectid, accountid)
    )
  `;
  
  connection.query(createTableSql, (createError) => {
    if (createError) {
      console.error('Error creating project_members table:', createError);
      return res.status(500).send('Error creating members table: ' + createError.message);
    }
    
    // Insert members
    const memberValues = membersList.map(member => [projectId, member.id]);
    const insertMembersSql = 'INSERT INTO project_members (projectid, accountid) VALUES ?';
    
    connection.query(insertMembersSql, [memberValues], (membersError) => {
      if (membersError) {
        console.error('Error adding project members:', membersError);
        return res.status(500).send('Error adding members: ' + membersError.message);
      }
      
      console.log('Project members added successfully');
      const redirectPath = user.roleid === 1 ? '/admin' : '/lecturer';
      res.redirect(redirectPath);
    });
  });
}

app.get('/editISLP/:projectid', checkAuthenticated, checkRole(1, 2), (req, res) => {
  const projectid = req.params.projectid;
  const projectSql = 'SELECT * FROM project WHERE projectid = ?';
  
  connection.query(projectSql, [projectid], (error, projectResults) => {
    if (error) return res.status(500).send('Error retrieving project by ID');
    if (projectResults.length === 0) return res.status(404).send('ISLP not found');
    
    // Check if the current user can edit this project
    const project = projectResults[0];
    const canEdit = req.session.user.roleid === 1 || // Admin can edit all
                    parseInt(project.project_head) === req.session.user.accountid; // Project head can edit
    
    if (!canEdit) {
      return res.status(403).send('Access denied. You can only edit projects you created.');
    }
    
    // Get lecturers for project head dropdown (role ID 2)
    const lecturersSql = 'SELECT accountid, username, email, roleid FROM account WHERE roleid = 2';
    // Get students for members dropdown (role ID 3)
    const studentsSql = 'SELECT accountid, username, email, roleid FROM account WHERE roleid = 3';
    // Get all status options
    const statusSql = 'SELECT statusid, name, description FROM status ORDER BY statusid';
    
    connection.query(lecturersSql, (lecturerError, lecturerResults) => {
      if (lecturerError) {
        console.error('Error fetching lecturers:', lecturerError);
        return res.status(500).send('Error fetching lecturers');
      }
      
      connection.query(studentsSql, (studentError, studentResults) => {
        if (studentError) {
          console.error('Error fetching students:', studentError);
          return res.status(500).send('Error fetching students');
        }
        
        connection.query(statusSql, (statusError, statusResults) => {
          if (statusError) {
            console.error('Error fetching status options:', statusError);
            return res.status(500).send('Error fetching status options');
          }
          
          // Get existing project members
          const membersSql = `
            SELECT pm.*, acc.username, acc.email, acc.roleid
            FROM project_members pm
            JOIN account acc ON pm.accountid = acc.accountid
            WHERE pm.projectid = ?
            ORDER BY acc.username
          `;
          
          connection.query(membersSql, [projectid], (membersError, membersResults) => {
            if (membersError) {
              console.error('Error loading members:', membersError);
              membersResults = []; // Continue without members if there's an error
            }
            
            res.render('editISLP', { 
              project: projectResults[0], 
              lecturers: lecturerResults,
              students: studentResults,
              existingMembers: membersResults,
              statusOptions: statusResults,
              currentUser: req.session.user 
            });
          });
        });
      });
    });
  });
});

app.post('/editISLP/:projectid', checkAuthenticated, checkRole(1, 2), (req, res) => {
  const projectid = req.params.projectid;
  
  // First check if the project exists and if the user has permission to edit it
  const checkOwnershipSql = 'SELECT project_head FROM project WHERE projectid = ?';
  connection.query(checkOwnershipSql, [projectid], (checkError, checkResults) => {
    if (checkError) return res.status(500).send('Error checking project ownership');
    if (checkResults.length === 0) return res.status(404).send('Project not found');
    
    // Check if the current user can edit this project
    const project = checkResults[0];
    const canEdit = req.session.user.roleid === 1 || // Admin can edit all
                    parseInt(project.project_head) === req.session.user.accountid; // Project head can edit
    
    if (!canEdit) {
      return res.status(403).send('Access denied. You can only edit projects you created.');
    }
    
    const { project_title, project_head, description, project_start, project_end, members, status_statusid } = req.body;

    // Preserve original project head - don't change ownership unless admin explicitly wants to
    const actualProjectHead = project.project_head; // Keep original owner

    // Parse members JSON string
    let membersList = [];
    if (members && members.trim() !== '') {
      try {
        membersList = JSON.parse(members);
      } catch (error) {
        console.error('Error parsing members:', error);
        return res.status(400).send('Invalid members data');
      }
    }

    const updateFields = { project_title, project_head: actualProjectHead, description, project_start, project_end, status_statusid };
    const fields = Object.keys(updateFields);
    const values = Object.values(updateFields);

    const sql = `UPDATE project SET ${fields.map(field => `${field} = ?`).join(', ')} WHERE projectid = ?`;
    values.push(projectid);

    connection.query(sql, values, (error, results) => {
      if (error) return res.status(500).send('Error updating project');
      
      // Update project members
      updateProjectMembers(projectid, membersList, res, req.session.user);
    });
  });
});

// Helper function to update project members
function updateProjectMembers(projectId, membersList, res, user) {
  // First, delete existing members
  const deleteSql = 'DELETE FROM project_members WHERE projectid = ?';
  
  connection.query(deleteSql, [projectId], (deleteError) => {
    if (deleteError) {
      console.error('Error deleting existing members:', deleteError);
      return res.status(500).send('Error updating members: ' + deleteError.message);
    }
    
    // Insert new members if any
    if (membersList && membersList.length > 0) {
      const memberValues = membersList.map(member => [projectId, member.id]);
      const insertMembersSql = 'INSERT INTO project_members (projectid, accountid) VALUES ?';
      
      connection.query(insertMembersSql, [memberValues], (membersError) => {
        if (membersError) {
          console.error('Error adding updated project members:', membersError);
          return res.status(500).send('Error updating members: ' + membersError.message);
        }
        
        console.log('Project members updated successfully');
        const redirectPath = user.roleid === 1 ? '/admin' : '/lecturer';
        res.redirect(redirectPath);
      });
    } else {
      console.log('No members to add during update');
      const redirectPath = user.roleid === 1 ? '/admin' : '/lecturer';
      res.redirect(redirectPath);
    }
  });
}

app.get('/deleteISLP/:projectid', checkAuthenticated, checkRole(1, 2), (req, res) => {
  const { projectid } = req.params;

  // Check if user has permission to delete this project
  const checkPermissionSql = 'SELECT * FROM project WHERE projectid = ? AND (? = 1 OR project_head = ?)';
  
  connection.query(checkPermissionSql, [projectid, req.session.user.roleid, req.session.user.accountid], (permErr, permResults) => {
    if (permErr || permResults.length === 0) {
      req.flash('error', 'You do not have permission to delete this project or project not found');
      return res.redirect('/admin');
    }

    // Start transaction to ensure data consistency
    connection.beginTransaction((transErr) => {
      if (transErr) {
        console.error('Transaction error:', transErr);
        req.flash('error', 'Error starting deletion process');
        return res.redirect('/admin');
      }

      // Step 1: Delete project members
      const deleteMembersSql = 'DELETE FROM project_members WHERE projectid = ?';
      
      connection.query(deleteMembersSql, [projectid], (memberErr) => {
        if (memberErr) {
          return connection.rollback(() => {
            console.error('Error deleting project members:', memberErr);
            req.flash('error', 'Error deleting project members');
            res.redirect('/admin');
          });
        }

        // Step 2: Delete submissions (if table exists)
        const deleteSubmissionsSql = 'DELETE FROM submissions WHERE projectid = ?';
        
        connection.query(deleteSubmissionsSql, [projectid], (subErr) => {
          // Don't fail if submissions table doesn't exist
          if (subErr && !subErr.message.includes("doesn't exist")) {
            return connection.rollback(() => {
              console.error('Error deleting submissions:', subErr);
              req.flash('error', 'Error deleting project submissions');
              res.redirect('/admin');
            });
          }

          // Step 3: Delete any other related records (add more if needed)
          // Example: DELETE FROM project_files WHERE projectid = ?
// Example: DELETE FROM project_comments WHERE projectid = ?


          // Step 4: Finally delete the project
          const deleteProjectSql = 'DELETE FROM project WHERE projectid = ?';
          
          connection.query(deleteProjectSql, [projectid], (projErr) => {
            if (projErr) {
              return connection.rollback(() => {
                console.error('Error deleting project:', projErr);
                req.flash('error', 'Error deleting project');
                res.redirect('/admin');
              });
            }

            // Commit the transaction
            connection.commit((commitErr) => {
              if (commitErr) {
                return connection.rollback(() => {
                  console.error('Commit error:', commitErr);
                  req.flash('error', 'Error completing deletion');
                  res.redirect('/admin');
                });
              }

              req.flash('success', 'Project deleted successfully!');
              
              // Redirect based on user role
              if (req.session.user.roleid === 1) {
                res.redirect('/admin');
              } else {
                res.redirect('/lecturer');
              }
            });
          });
        });
      });
    });
  });
});

app.get('/contact', (req, res) => {
  res.render('contac');
});

app.get('/profile', checkAuthenticated, (req, res) => {
  res.render('profile', { user: req.session.user });
});

app.post('/updateProfile', checkAuthenticated, (req, res) => {
  const { username, email, phone, password } = req.body;
  const accountid = req.session.user.accountid;

  // Build update query dynamically based on provided fields
  let updateFields = [];
  let values = [];

  if (username) {
    updateFields.push('username = ?');
    values.push(username);
  }
  if (email) {
    updateFields.push('email = ?');
    values.push(email);
  }
  if (phone) {
    updateFields.push('phone = ?');
    values.push(phone);
  }
  if (password && password.trim() !== '') {
    updateFields.push('password = ?');
    values.push(hashPassword(password)); // Hash the new password
  }

  if (updateFields.length === 0) {
    return res.redirect('/profile');
  }

  values.push(accountid);
  const sql = `UPDATE account SET ${updateFields.join(', ')} WHERE accountid = ?`;

  connection.query(sql, values, (error, results) => {
    if (error) {
      console.error('Error updating profile:', error);
      return res.status(500).send('Error updating profile');
    }

    // Update session data
    connection.query('SELECT * FROM account WHERE accountid = ?', [accountid], (selectError, selectResults) => {
      if (selectError) {
        console.error('Error fetching updated user data:', selectError);
      } else if (selectResults.length > 0) {
        req.session.user = selectResults[0];
      }
      res.redirect('/profile');
    });
  });
});

app.post('/submit', (req, res) => {
  const { name, email, contact_no, comments } = req.body;
  const sql = 'INSERT INTO feedback (name, email, contact_no, comments) VALUES (?, ?, ?, ?)';
  connection.query(sql, [name, email, contact_no, comments], (error, results) => {
    if (error) return res.status(500).send('Error adding feedback');
    res.render('submit', { name, email, contact_no, comments });
  });
});

app.get('/feedback', checkAuthenticated, checkRole(1, 2), (req, res) => {
  // Get projects filtered by current user (only show projects they created/own)
  const sql = `
    SELECT p.*, s.name as project_status 
    FROM project p 
    LEFT JOIN status s ON p.status_statusid = s.statusid
    WHERE p.project_head = ?
    ORDER BY p.projectid DESC
  `;
  
  connection.query(sql, [req.session.user.accountid], (error, results) => {
    if (error) {
      console.error('Error fetching user projects:', error);
      return res.status(500).send('Error loading your projects');
    }
    res.render('myproject', { 
      projects: results,
      currentUser: req.session.user 
    });
  });
});

app.get('/myproject', checkAuthenticated, (req, res) => {
  if (req.session.user.roleid === 3) {
    // Student: Get ONLY projects where they are APPROVED members
    const sql = `
      SELECT p.*, s.name as project_status,
             CASE 
               WHEN CURDATE() < p.project_start THEN 'Upcoming'
               WHEN CURDATE() BETWEEN p.project_start AND p.project_end THEN 'Ongoing'
               WHEN CURDATE() > p.project_end THEN 'Completed'
               ELSE s.name
             END as dynamic_status
      FROM project p 
      LEFT JOIN status s ON p.status_statusid = s.statusid
      INNER JOIN project_members pm ON p.projectid = pm.projectid
      WHERE pm.accountid = ? AND pm.status = 'approved'
      ORDER BY p.project_start DESC
    `;
    
    connection.query(sql, [req.session.user.accountid], (error, results) => {
      if (error) {
        console.error('Error fetching student projects:', error);
        return res.status(500).send('Error loading your projects');
      }
      res.render('myproject', { 
        projects: results,
        currentUser: req.session.user 
      });
    });
  } else {
    // Lecturer/Admin: Get projects they created/own (unchanged)
    const sql = `
      SELECT p.*, s.name as project_status,
             CASE 
               WHEN CURDATE() < p.project_start THEN 'Upcoming'
               WHEN CURDATE() BETWEEN p.project_start AND p.project_end THEN 'Ongoing'
               WHEN CURDATE() > p.project_end THEN 'Completed'
               ELSE s.name
             END as dynamic_status
      FROM project p 
      LEFT JOIN status s ON p.status_statusid = s.statusid
      WHERE p.project_head = ?
      ORDER BY p.project_start DESC
    `;
    
    connection.query(sql, [req.session.user.accountid], (error, results) => {
      if (error) {
        console.error('Error fetching user projects:', error);
        return res.status(500).send('Error loading your projects');
      }
      res.render('myproject', { 
        projects: results,
        currentUser: req.session.user 
      });
    });
  }
});

app.get('/addPost/:projectid', checkAuthenticated, checkRole(1, 2, 3), (req, res) => {
  const { projectid } = req.params;
  
  // Get project details
  const projectSql = 'SELECT * FROM project WHERE projectid = ?';
  
  connection.query(projectSql, [projectid], (err, projectResults) => {
    if (err || projectResults.length === 0) return res.status(404).send('Project not found');
    
    const project = projectResults[0];
    
    // All authenticated users can add posts to any project
    res.render('addPost', { project: project });
  });
});

app.post('/addPost/:projectid', checkAuthenticated, checkRole(1, 2, 3), upload.single('post_image'), (req, res) => {
  const { projectid } = req.params;
  const { description } = req.body;
  const post_image = req.file ? req.file.filename : null; // Get uploaded image filename
  
  // Get project details to verify it exists
  const projectSql = 'SELECT * FROM project WHERE projectid = ?';
  
  connection.query(projectSql, [projectid], (err, projectResults) => {
    if (err || projectResults.length === 0) return res.status(404).send('Project not found');
    
    // All authenticated users can add posts to any project
    const accountid = req.session.user.accountid;
    const sql = `INSERT INTO submissions (accountid, projectid, description, post_image, submission_date) VALUES (?, ?, ?, ?, NOW())`;
    
    connection.query(sql, [accountid, projectid, description, post_image], (insertErr, result) => {
      if (insertErr) {
        console.error('Error inserting submission:', insertErr);
        return res.status(500).send('Failed to add submission');
      }
      res.redirect(`/ISLP/${projectid}`);
    });
  });
});

app.get('/editPost/:submissionsid', checkAuthenticated, checkRole(1, 2, 3), (req, res) => {
  const { submissionsid } = req.params;
  const sql = 'SELECT submissionsid, projectid, description, post_image, accountid FROM submissions WHERE submissionsid = ?';

  connection.query(sql, [submissionsid], (err, results) => {
    if (err || results.length === 0) return res.status(404).send('Post not found');
    
    const post = results[0];
    // All users (including admin) can only edit posts they created
    if (post.accountid !== req.session.user.accountid) {
      return res.status(403).send('Access denied. You can only edit posts you created.');
    }
    
    res.render('editPost', { post: post });
  });
});


app.post('/editPost/:submissionsid', checkAuthenticated, checkRole(1, 2, 3), upload.single('post_image'), (req, res) => {
  const { submissionsid } = req.params;
  const { description, delete_image } = req.body;
  const new_post_image = req.file ? req.file.filename : null;

  // First check if the post exists and if the user has permission to edit it
  const checkOwnershipSql = 'SELECT accountid, projectid, post_image FROM submissions WHERE submissionsid = ?';
  connection.query(checkOwnershipSql, [submissionsid], (checkErr, checkResults) => {
    if (checkErr || checkResults.length === 0) return res.status(404).send('Post not found');
    
    const post = checkResults[0];
    // All users (including admin) can only edit posts they created
    if (post.accountid !== req.session.user.accountid) {
      return res.status(403).send('Access denied. You can only edit posts you created.');
    }

    // Determine the final image value
    let final_post_image = post.post_image; // Keep existing image by default
    
    if (delete_image === 'true') {
      // User wants to delete the image
      final_post_image = null;
    } else if (new_post_image) {
      // User uploaded a new image
      final_post_image = new_post_image;
    }

    const sql = 'UPDATE submissions SET description = ?, post_image = ? WHERE submissionsid = ?';
    connection.query(sql, [description, final_post_image, submissionsid], (err, result) => {
      if (err) return res.status(500).send('Failed to update post');
      res.redirect(`/ISLP/${post.projectid}`);
    });
  });
});

app.get('/deletePost/:submissionsid', checkAuthenticated, checkRole(1, 2, 3), (req, res) => {
  const { submissionsid } = req.params;

  // Get post details and check ownership
  const getPostSql = `
    SELECT s.projectid, s.accountid, a.roleid as post_author_role
    FROM submissions s
    JOIN account a ON s.accountid = a.accountid
    WHERE s.submissionsid = ?
  `;
  connection.query(getPostSql, [submissionsid], (err, results) => {
    if (err || results.length === 0) return res.status(404).send('Post not found');
    
    const post = results[0];
    
    // Check permissions based on user role
    if (req.session.user.roleid === 1) {
      // Admin can delete any post - no restrictions
    } else if (req.session.user.roleid === 3) {
      // Students can only delete their own posts
      if (post.accountid !== req.session.user.accountid) {
        return res.status(403).send('Access denied. Students can only delete posts they created.');
      }
    } else if (req.session.user.roleid === 2) {
      // Lecturers can delete their own posts OR student posts, but NOT other lecturer posts
      if (post.accountid !== req.session.user.accountid && post.post_author_role === 2) {
        return res.status(403).send('Access denied. Lecturers cannot delete posts created by other lecturers.');
      }
    }
    
    const projectid = post.projectid;

    const deleteSql = 'DELETE FROM submissions WHERE submissionsid = ?';
    connection.query(deleteSql, [submissionsid], (deleteErr) => {
      if (deleteErr) return res.status(500).send('Failed to delete post');
      res.redirect(`/ISLP/${projectid}`);
    });
  });
});

// API routes for handling post likes
app.post('/api/like/:submissionsid', checkAuthenticated, (req, res) => {
  const { submissionsid } = req.params;
  const accountid = req.session.user.accountid;

  // Check if user already liked this post
  const checkLikeSql = 'SELECT * FROM post_likes WHERE submissionsid = ? AND accountid = ?';
  
  connection.query(checkLikeSql, [submissionsid, accountid], (checkErr, checkResults) => {
    if (checkErr) {
      console.error('Error checking like status:', checkErr);
      return res.status(500).json({ error: 'Database error' });
    }

    if (checkResults.length > 0) {
      // User already liked this post, so unlike it
      const deleteLikeSql = 'DELETE FROM post_likes WHERE submissionsid = ? AND accountid = ?';
      
      connection.query(deleteLikeSql, [submissionsid, accountid], (deleteErr) => {
        if (deleteErr) {
          console.error('Error removing like:', deleteErr);
          return res.status(500).json({ error: 'Failed to remove like' });
        }

        // Get updated like count
        const countSql = 'SELECT COUNT(*) as like_count FROM post_likes WHERE submissionsid = ?';
        connection.query(countSql, [submissionsid], (countErr, countResults) => {
          if (countErr) {
            console.error('Error getting like count:', countErr);
            return res.status(500).json({ error: 'Failed to get like count' });
          }

          res.json({
            liked: false,
            like_count: countResults[0].like_count
          });
        });
      });
    } else {
      // User hasn't liked this post, so add a like
      const insertLikeSql = 'INSERT INTO post_likes (submissionsid, accountid) VALUES (?, ?)';
      
      connection.query(insertLikeSql, [submissionsid, accountid], (insertErr) => {
        if (insertErr) {
          console.error('Error adding like:', insertErr);
          return res.status(500).json({ error: 'Failed to add like' });
        }

        // Get updated like count
        const countSql = 'SELECT COUNT(*) as like_count FROM post_likes WHERE submissionsid = ?';
        connection.query(countSql, [submissionsid], (countErr, countResults) => {
          if (countErr) {
            console.error('Error getting like count:', countErr);
            return res.status(500).json({ error: 'Failed to get like count' });
          }

          res.json({
            liked: true,
            like_count: countResults[0].like_count
          });
        });
      });
    }
  });
});

// Signup routes for students to join projects
app.get('/signup/:projectid', checkAuthenticated, checkRole(3), (req, res) => {
  const { projectid } = req.params;
  const accountid = req.session.user.accountid;

  // First check if project exists
  const projectSql = 'SELECT * FROM project WHERE projectid = ?';
  
  connection.query(projectSql, [projectid], (err, projectResults) => {
    if (err || projectResults.length === 0) {
      return res.status(404).send('Project not found');
    }

    const project = projectResults[0];

    // Check if user is already a member and get their status
    const checkMemberSql = 'SELECT * FROM project_members WHERE projectid = ? AND accountid = ?';
    
    connection.query(checkMemberSql, [projectid, accountid], (memberErr, memberResults) => {
      if (memberErr) {
        console.error('Error checking membership:', memberErr);
        return res.status(500).send('Error checking membership');
      }

      const isMember = memberResults.length > 0;
      const memberStatus = isMember ? memberResults[0].status : null;

      // Always render the signup page with all necessary data
      res.render('signup', { 
        project: project,
        currentUser: req.session.user,
        isMember: isMember,
        memberStatus: memberStatus, // Add this line
        errors: req.flash('error'),
        messages: req.flash('success')
      });
    });
  });
});

// Replace your existing signup POST route with this:
app.post('/signup/:projectid', checkAuthenticated, checkRole(3), (req, res) => {
  const { projectid } = req.params;
  const accountid = req.session.user.accountid;

  // Check if user already has a request or is already a member
  const checkMemberSql = 'SELECT * FROM project_members WHERE projectid = ? AND accountid = ?';
  
  connection.query(checkMemberSql, [projectid, accountid], (memberErr, memberResults) => {
    if (memberErr) {
      console.error('Error checking membership:', memberErr);
      req.flash('error', 'Error checking membership');
      return res.redirect(`/signup/${projectid}`);
    }

    if (memberResults.length > 0) {
      const existingStatus = memberResults[0].status;
      if (existingStatus === 'pending') {
        req.flash('error', 'Your request is already pending approval');
      } else if (existingStatus === 'approved') {
        req.flash('error', 'You are already a member of this project');
      } else if (existingStatus === 'rejected') {
        req.flash('error', 'Your previous request was rejected. Please contact the project lead.');
      }
      return res.redirect(`/signup/${projectid}`);
    }

    // Insert the user with pending status
    const insertMemberSql = 'INSERT INTO project_members (projectid, accountid, status) VALUES (?, ?, ?)';
    
    connection.query(insertMemberSql, [projectid, accountid, 'pending'], (insertErr, insertResult) => {
      if (insertErr) {
        console.error('Error submitting join request:', insertErr);
        req.flash('error', 'Error submitting join request');
        return res.redirect(`/signup/${projectid}`);
      }
      
      req.flash('success', 'Join request submitted! Waiting for approval from project facilitator.');
      res.redirect(`/signup/${projectid}`);
    });
  });
});

// Add these routes before the PORT section at the end of your app.js file

// Account management routes for admin
app.get('/accounts', checkAuthenticated, checkRole(1), (req, res) => {
  const sql = `
    SELECT accountid, username, email, phone, roleid, profile_description
    FROM account 
    ORDER BY accountid DESC
  `;
  connection.query(sql, (error, results) => { 
    if (error) {
      console.error('Error fetching accounts:', error);
      return res.status(500).send('Error loading accounts');
    }
    
    // Add role names manually since there's no role table
    const accountsWithRoles = results.map(account => {
      let role_name;
      switch(account.roleid) {
        case 1:
          role_name = 'Admin';
          break;
        case 2:
          role_name = 'Lecturer';
          break;
        case 3:
          role_name = 'Student';
          break;
        default:
          role_name = 'Unknown';
      }
      return {
        ...account,
        role_name: role_name
      };
    });
    
    res.render('accounts', { 
      accounts: accountsWithRoles,
      currentUser: req.session.user,
      errors: req.flash('error'),
      messages: req.flash('success')
    }); 
  }); 
});

// Add new account page
app.get('/addAccount', checkAuthenticated, checkRole(1), (req, res) => {
  // Since there's no role table, we'll use hardcoded roles
  const roles = [
    { roleid: 1, name: 'Admin' },
    { roleid: 2, name: 'Lecturer' },
    { roleid: 3, name: 'Student' }
  ];
  
  res.render('addAccount', { 
    roles: roles,
    currentUser: req.session.user,
    errors: req.flash('error'),
    messages: req.flash('success')
  });
});

// Add new account POST
app.post('/addAccount', checkAuthenticated, checkRole(1), (req, res) => {
  const { username, email, password, phone, roleid, profile_description } = req.body;

  // Validation
  if (!username || !email || !password || !roleid) {
    req.flash('error', 'Username, email, password, and role are required.');
    return res.redirect('/addAccount');
  }

  // Check if email already exists
  const checkEmailSql = 'SELECT accountid FROM account WHERE email = ?';
  connection.query(checkEmailSql, [email], (checkErr, checkResults) => {
    if (checkErr) {
      console.error('Error checking email:', checkErr);
      req.flash('error', 'Error checking email availability');
      return res.redirect('/addAccount');
    }

    if (checkResults.length > 0) {
      req.flash('error', 'Email already exists. Please use a different email.');
      return res.redirect('/addAccount');
    }

    // Hash the password before storing
    const hashedPassword = hashPassword(password);

    // Insert new account
    const insertSql = 'INSERT INTO account (username, email, password, phone, roleid, profile_description) VALUES (?, ?, ?, ?, ?, ?)';
    connection.query(insertSql, [username, email, hashedPassword, phone || null, roleid, profile_description || null], (insertErr, insertResult) => {
      if (insertErr) {
        console.error('Error adding account:', insertErr);
        req.flash('error', 'Failed to create account');
        return res.redirect('/addAccount');
      }
      
      req.flash('success', 'Account created successfully!');
      res.redirect('/accounts');
    });
  });
});

// Edit account page
app.get('/editAccount/:accountid', checkAuthenticated, checkRole(1), (req, res) => {
  const { accountid } = req.params;
  
  // Get account details
  const accountSql = 'SELECT * FROM account WHERE accountid = ?';
  
  connection.query(accountSql, [accountid], (accountErr, accountResults) => {
    if (accountErr || accountResults.length === 0) {
      req.flash('error', 'Account not found');
      return res.redirect('/accounts');
    }
    
    // Hardcoded roles since there's no role table
    const roles = [
      { roleid: 1, name: 'Admin' },
      { roleid: 2, name: 'Lecturer' },
      { roleid: 3, name: 'Student' }
    ];
    
    res.render('editAccount', { 
      account: accountResults[0],
      roles: roles,
      currentUser: req.session.user,
      errors: req.flash('error'),
      messages: req.flash('success')
    });
  });
});

// Edit account POST
app.post('/editAccount/:accountid', checkAuthenticated, checkRole(1), (req, res) => {
  const { accountid } = req.params;
  const { username, email, password, phone, roleid, profile_description } = req.body;

  // Validation
  if (!username || !email || !roleid) {
    req.flash('error', 'Username, email, and role are required.');
    return res.redirect(`/editAccount/${accountid}`);
  }

  // Check if email already exists for other accounts
  const checkEmailSql = 'SELECT accountid FROM account WHERE email = ? AND accountid != ?';
  connection.query(checkEmailSql, [email, accountid], (checkErr, checkResults) => {
    if (checkErr) {
      console.error('Error checking email:', checkErr);
      req.flash('error', 'Error checking email availability');
      return res.redirect(`/editAccount/${accountid}`);
    }

    if (checkResults.length > 0) {
      req.flash('error', 'Email already exists. Please use a different email.');
      return res.redirect(`/editAccount/${accountid}`);
    }

    // Build update query
    let updateFields = ['username = ?', 'email = ?', 'roleid = ?'];
    let values = [username, email, roleid];

    if (password && password.trim() !== '') {
      updateFields.push('password = ?');
      values.push(hashPassword(password)); // Hash the new password
    }

    if (phone !== undefined) {
      updateFields.push('phone = ?');
      values.push(phone || null);
    }

    if (profile_description !== undefined) {
      updateFields.push('profile_description = ?');
      values.push(profile_description || null);
    }

    values.push(accountid);

    const updateSql = `UPDATE account SET ${updateFields.join(', ')} WHERE accountid = ?`;
    connection.query(updateSql, values, (updateErr, updateResult) => {
      if (updateErr) {
        console.error('Error updating account:', updateErr);
        req.flash('error', 'Failed to update account');
        return res.redirect(`/editAccount/${accountid}`);
      }
      
      req.flash('success', 'Account updated successfully!');
      res.redirect('/accounts');
    });
  });
});

// Delete account
app.get('/deleteAccount/:accountid', checkAuthenticated, checkRole(1), (req, res) => {
  const { accountid } = req.params;

  // Prevent admin from deleting their own account
  if (parseInt(accountid) === req.session.user.accountid) {
    req.flash('error', 'You cannot delete your own account.');
    return res.redirect('/accounts');
  }

  // Check if account has any projects or submissions before deleting
  const checkProjectsSql = 'SELECT COUNT(*) as project_count FROM project WHERE project_head = ?';
  const checkSubmissionsSql = 'SELECT COUNT(*) as submission_count FROM submissions WHERE accountid = ?';
  const checkMembershipSql = 'SELECT COUNT(*) as membership_count FROM project_members WHERE accountid = ?';

  connection.query(checkProjectsSql, [accountid], (projErr, projResults) => {
    if (projErr) {
      console.error('Error checking projects:', projErr);
      req.flash('error', 'Error checking account dependencies');
      return res.redirect('/accounts');
    }

    const projectCount = projResults[0].project_count;

    connection.query(checkSubmissionsSql, [accountid], (subErr, subResults) => {
      if (subErr) {
        console.error('Error checking submissions:', subErr);
        req.flash('error', 'Error checking account dependencies');
        return res.redirect('/accounts');
      }

      const submissionCount = subResults[0].submission_count;

      connection.query(checkMembershipSql, [accountid], (memErr, memResults) => {
        if (memErr) {
          console.error('Error checking memberships:', memErr);
          req.flash('error', 'Error checking account dependencies');
          return res.redirect('/accounts');
        }

        const membershipCount = memResults[0].membership_count;

        // If account has dependencies, show warning
        if (projectCount > 0 || submissionCount > 0 || membershipCount > 0) {
          req.flash('error', `Cannot delete account. User has ${projectCount} projects, ${submissionCount} submissions, and ${membershipCount} project memberships. Please transfer or remove these first.`);
          return res.redirect('/accounts');
        }

        // Safe to delete
        const deleteSql = 'DELETE FROM account WHERE accountid = ?';
        connection.query(deleteSql, [accountid], (deleteErr, deleteResult) => {
          if (deleteErr) {
            console.error('Error deleting account:', deleteErr);
            req.flash('error', 'Failed to delete account');
            return res.redirect('/accounts');
          }
          
          req.flash('success', 'Account deleted successfully!');
          res.redirect('/accounts');
        });
      });
    });
  });
});

// Route to view pending member requests
app.get('/memberRequests', checkAuthenticated, checkRole(1, 2), (req, res) => {
  let sql;
  let params = [];

  if (req.session.user.roleid === 1) {
    // Admin can see all pending requests
    sql = `
      SELECT pm.*, p.project_title, p.project_head, a.username, a.email
      FROM project_members pm
      JOIN project p ON pm.projectid = p.projectid
      JOIN account a ON pm.accountid = a.accountid
      WHERE pm.status = 'pending'
      ORDER BY pm.added_date DESC
    `;
  } else {
    // Lecturer can only see requests for their projects
    sql = `
      SELECT pm.*, p.project_title, p.project_head, a.username, a.email
      FROM project_members pm
      JOIN project p ON pm.projectid = p.projectid
      JOIN account a ON pm.accountid = a.accountid
      WHERE pm.status = 'pending' AND p.project_head = ?
      ORDER BY pm.added_date DESC
    `;
    params = [req.session.user.accountid];
  }

  connection.query(sql, params, (error, results) => {
    if (error) {
      console.error('Error fetching member requests:', error);
      return res.status(500).send('Error loading member requests');
    }
    
    res.render('memberRequests', { 
      requests: results,
      currentUser: req.session.user,
      errors: req.flash('error'),
      messages: req.flash('success')
    });
  });
});

// Route to approve/reject member requests
app.post('/memberRequest/:id/:action', checkAuthenticated, checkRole(1, 2), (req, res) => {
  const requestId = req.params.id;
  const action = req.params.action; // 'approve' or 'reject'
  
  if (!['approve', 'reject'].includes(action)) {
    req.flash('error', 'Invalid action');
    return res.redirect('/memberRequests');
  }

  // First check if the request exists and if the user has permission
  const checkSql = `
    SELECT pm.*, p.project_head
    FROM project_members pm
    JOIN project p ON pm.projectid = p.projectid
    WHERE pm.id = ? AND pm.status = 'pending'
  `;

  connection.query(checkSql, [requestId], (checkErr, checkResults) => {
    if (checkErr || checkResults.length === 0) {
      req.flash('error', 'Request not found or already processed');
      return res.redirect('/memberRequests');
    }

    const request = checkResults[0];
    
    // Check permissions
    if (req.session.user.roleid !== 1 && request.project_head !== req.session.user.accountid) {
      req.flash('error', 'You can only manage requests for your own projects');
      return res.redirect('/memberRequests');
    }

    const newStatus = action === 'approve' ? 'approved' : 'rejected';
    const updateSql = 'UPDATE project_members SET status = ? WHERE id = ?';

    connection.query(updateSql, [newStatus, requestId], (updateErr) => {
      if (updateErr) {
        console.error('Error updating request status:', updateErr);
        req.flash('error', 'Error processing request');
        return res.redirect('/memberRequests');
      }

      const message = action === 'approve' ? 'Student approved successfully!' : 'Request rejected successfully.';
      req.flash('success', message);
      res.redirect('/memberRequests');
    });
  });
});

// Route to hash all existing passwords (run this once to convert existing passwords)
app.get('/hashAllPasswords', checkAuthenticated, checkRole(1), (req, res) => {
  // Get all accounts with plain text passwords (passwords without ':')
  const sql = "SELECT accountid, password FROM account WHERE password NOT LIKE '%:%'";
  
  connection.query(sql, (err, results) => {
    if (err) {
      console.error('Error fetching accounts:', err);
      return res.status(500).send('Error fetching accounts');
    }
    
    if (results.length === 0) {
      return res.send('All passwords are already hashed!');
    }
    
    let processedCount = 0;
    const totalCount = results.length;
    
    results.forEach((account) => {
      const hashedPassword = hashPassword(account.password);
      const updateSql = 'UPDATE account SET password = ? WHERE accountid = ?';
      
      connection.query(updateSql, [hashedPassword, account.accountid], (updateErr) => {
        if (updateErr) {
          console.error(`Error updating password for account ${account.accountid}:`, updateErr);
        }
        
        processedCount++;
        
        if (processedCount === totalCount) {
          res.send(`Successfully hashed ${totalCount} passwords!`);
        }
      });
    });
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}/login`));
