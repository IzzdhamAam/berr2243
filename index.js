const express = require('express');
const app = express();
app.use(express.json());
const port = process.env.PORT || 3000;
const { MongoClient, ServerApiVersion } = require('mongodb');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const secretKey = 'kucingbesar'; 
const bodyParser = require('body-parser');
app.use(bodyParser.json());
const cors = require('cors');
const apiUrl = process.env.NODE_ENV === 'production' ? 'https://dzimz.azurewebsites.net' : 'http://localhost:3000';
const uri = "mongodb+srv://b122310299:Kickflip.09@cluster0.mxtvq.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

app.use(cors({
  origin: 'https://dzimz.azurewebsites.net',
  methods: 'GET,POST',
}));

function verifyToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) {
    return res.status(403).send('A token is required for authentication');
  }

  try {
    const decoded = jwt.verify(token, secretKey);
    req.user = decoded;
  } catch (err) {
    return res.status(401).send('Invalid Token');
  }
  return next();
}


async function checkBlacklist(token) {
  console.log("Checking token against blacklist:", token);
  const blacklistedToken = await client.db("mytaxiutem").collection("blacklisted_tokens").findOne({ token });
  if (blacklistedToken) {
    console.log("Token is blacklisted:", token);
    return true; 
  }
  console.log("Token is not blacklisted:", token);
  return false; 
}

app.get('/test', (req, res) => {
  res.send('Server is working!');
});

//first page
app.get('/', (req, res) => {
  res.send(`Welcome To MyTaxi UTeM! Please Log In Or Register For First Time User!`);
});

// Login admin
app.get('/admin/login', async (req, res) => {
  const user = await client.db("mytaxiutem").collection("admin").findOne(
    { username: { $eq: req.body.username } }
  );

  if (!user) {
    res.send('Login Failed. Please Check Your Username');
    return;
  }

  const match = bcrypt.compareSync(req.body.password, user.password);

  if (match) {
    const token = jwt.sign({ username: user.username, role: 'admin', name : user.name }, 'kucingbesar', { expiresIn: '2h' });
    return res.status(200).json({ message: 'Login Success. Welcome To MyTaxi UTeM admin' + req.body.name , token });
  }
  else {
    return res.status(401).json('Login Failed. Please Check Your Password');
  }
});

// Login driver
app.get('/driver/login', async (req, res) => {
  const user = await client.db("mytaxiutem").collection("driver").findOne(
    { username: { $eq: req.body.username } }
  );

  if (!user) {
    res.send('Login Failed. Please Check Your Username');
    return;
  }

  const match = bcrypt.compareSync(req.body.password, user.password);

  if (match) {
    const token = jwt.sign({ username: user.username, role: 'driver', name : user.name}, secretKey, { expiresIn: '2h' });
    res.send({ message: 'Login Success. Welcome To MyTaxi UTeM And Drive Safe' + req.body.name , token });
  } else {
    res.send('Login Failed. Please Check Your Password');
  }
});

// Login passenger
app.get('/passenger/login', async (req, res) => {
  const user = await client.db("mytaxiutem").collection("passenger").findOne(
    { username: { $eq: req.body.username } }
  );

  if (!user) {
    res.send('Login Failed. Please Check Your Username');
    return;
  }

  const match = bcrypt.compareSync(req.body.password, user.password);

  if (match) {
    const token = jwt.sign({ username: user.username, role: 'passenger', phone_number : user.phone_number, name : user.name }, secretKey, { expiresIn: '2h' });
    res.send({ message: 'Login Success. Welcome To MyTaxi UTeM And Have A Safe Ride' + req.body.name , token });
  } else {
    res.send('Login Failed. Please Check Your Password');
  }
});

//------------------------------------------------------------------------------------------------------------------------------------------

//register admin
app.post('/admin/register', async (req, res) => {  
  const user = await client.db("mytaxiutem").collection("admin").findOne (
   {username: {$eq: req.body.username}}
  )

  if (user){
   res.send('username exist')
   return
  }

   const hash = bcrypt.hashSync(req.body.password, saltRounds);
   
   client.db("mytaxiutem").collection("admin").insertOne({
      "name" : req.body.name,
      "username" : req.body.username,
      "password" : hash
   })
   res.send(' Register successfully ' + req.body.name)
})

//register driver
app.post('/driver/register', async (req, res) => {  
  const ic_number = await client.db("mytaxiutem").collection("driver").findOne (
   {ic_number: {$eq: req.body.ic_number}}
  )

  if (ic_number){
   res.send('Driver had registered')
   return
  }

   const hash = bcrypt.hashSync(req.body.password, saltRounds);
   
   client.db("mytaxiutem").collection("driver").insertOne({
      "name" : req.body.name,
      "ic_number"  : req.body.ic_number,
      "birthday" : req.body.birthday,
      "gender" : req.body.gender,
      "phone_number" : req.body.phone_number,
      "email" : req.body.email,
      "username" : req.body.username,
      "password" : hash,
      "emergency"  : req.body.emergency,
      "residential_address"  : req.body.residential_address,
      "license_number"  : req.body.license_number,
      "insurance_number"  : req.body.insurance_number,
      "vehicle_type"  : req.body.vehicle_type,
      "vehicle_manufacturer"  : req.body.vehicle_manufacturer,
      "vehicle_model" : req.body.vehicle_model,
      "vehicle_manufacturer_date"  : req.body.vehicle_manufacturer_date,
      "roadtax_date"  : req.body.roadtax_date,
      "bankaccount "  : req.body.bankaccount,
      "bankaccount_number"  : req.body.bankaccount_number,
      "createdAt" : new Date()
      
   })
   res.send('You Have Successfully Register As Driver! Happy Driving  ' +  req.body.name)
}) 

//register passenger
app.post('/passenger/register', async (req, res) => {  
  const user = await client.db("mytaxiutem").collection("passenger").findOne (
   {username: {$eq: req.body.username}}
  )

  if (user){
   res.send('username exist')
   return
  }

   const hash = bcrypt.hashSync(req.body.password, saltRounds);
   
   client.db("mytaxiutem").collection("passenger").insertOne({
      "name" : req.body.name,
      "phone_number" : req.body.phone_number,
      "email" : req.body.email,
      "username" : req.body.username,
      "password" : hash,
      "emergency"  : req.body.emergency,
      "birthday" : req.body.birthday,
      "gender" : req.body.gender,
      "refferal" : req.body.refferal,
      "createdAt": new Date()
   })
   res.send(' Thank You for registering MyTaxi UTeM ' + req.body.name + '! Here RM10 OFF for first ride :D')
})

//----------------------------------------------------------------------------------------------------------------------------------------
//passenger see profile
app.get('/passenger/profile', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      console.error('No token provided');
      return res.status(401).send('Unauthorized: No token provided');
    }
    const blacklistedToken = await client.db("mytaxiutem").collection("blacklisted_tokens").findOne({ token });
    if (blacklistedToken) {
      console.error('Token is blacklisted');
      return res.status(403).send('You have Log Out! Please Log In To Access');
    }
    jwt.verify(token, secretKey, async (err, user) => {
      if (err) {
        console.error('Token verification error:', err);
        return res.status(403).send('Forbidden: Invalid token');
      }
      if (user.role !== 'passenger') {
        console.error('Unauthorized role:', user.role);
        return res.status(403).send('Forbidden: Passenger role required');
      }

      try {
        const passengerProfile = await client.db("mytaxiutem").collection("passenger").findOne(
          { username: user.username } 
        );

        if (!passengerProfile) {
          return res.status(404).send('Profile not found');
        }
        res.json(passengerProfile);
      } catch (dbError) {
        console.error('Database query error:', dbError);
        res.status(500).send('Internal Server Error');
      }
    });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).send('Internal Server Error');
  }
});

//driver see profile
app.get('/driver/profile', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      console.error('No token provided');
      return res.status(401).send('Unauthorized: No token provided');
    }
    const blacklistedToken = await client.db("mytaxiutem").collection("blacklisted_tokens").findOne({ token });
    if (blacklistedToken) {
      console.error('Token is blacklisted');
      return res.status(403).send('You have Log Out! Please Log In To Access');
    }
    jwt.verify(token, secretKey, async (err, user) => {
      if (err) {
        console.error('Token verification error:', err);
        return res.status(403).send('Forbidden: Invalid token');
      }
      if (user.role !== 'driver') {
        console.error('Unauthorized role:', user.role);
        return res.status(403).send('Forbidden: Driver role required');
      }

      try {
        const passengerProfile = await client.db("mytaxiutem").collection("driver").findOne(
          { username: user.username } 
        );

        if (!passengerProfile) {
          return res.status(404).send('Profile not found');
        }
        res.json(passengerProfile);
      } catch (dbError) {
        console.error('Database query error:', dbError);
        res.status(500).send('Internal Server Error');
      }
    });

  } catch (error) {
    console.error('Error:', error);
    res.status(500).send('Internal Server Error');
  }
});

//update profile driver
app.patch('/driver/updateprofile', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      console.error('No token provided');
      return res.status(401).send('Unauthorized: No token provided');
    }

    const blacklistedToken = await client.db("mytaxiutem").collection("blacklisted_tokens").findOne({ token });
    if (blacklistedToken) {
      console.error('Token is blacklisted');
      return res.status(403).send('You have Log Out! Please Log In To Access');
    }
    jwt.verify(token, secretKey, async (err, user) => {
      if (err) {
        console.error('Token verification error:', err);
        return res.status(403).send('Forbidden: Invalid token');
      }
      if (user.role !== 'driver') {
        console.error('Unauthorized role:', user.role);
        return res.status(403).send('Forbidden: Driver role required');
      }
      const allowedUpdates = [
        "phone_number",
        "password",
        "emergency",
        "residential_address",
        "license_number",
        "insurance_number",
        "vehicle_type",
        "vehicle_manufacturer",
        "vehicle_model",
        "vehicle_manufacturer_date",
        "roadtax_date"
      ];

      const { password, ...updateData } = req.body;

      const filteredUpdates = {};
      for (const key of allowedUpdates) {
        if (updateData[key] !== undefined) {
          filteredUpdates[key] = updateData[key];
        }
      }
      if (password) {
        filteredUpdates.password = bcrypt.hashSync(password, saltRounds);
      }
      const driver = await client.db("mytaxiutem").collection("driver").findOne(
        { username: { $eq: user.username } }
      );

      if (!driver) {
        return res.status(404).send('Driver not found');
      }
      await client.db("mytaxiutem").collection("driver").updateOne(
        { username: { $eq: user.username } },
        { $set: filteredUpdates }
      );

      res.send('Driver information updated successfully');
    });

  } catch (error) {
    console.error('Error updating driver:', error);
    res.status(500).send('Internal Server Error');
  }
});

//update passenger
app.patch('/passenger/updateprofile', async (req, res) => {
  try {
    const { password, ...updateData } = req.body;

    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).send('Unauthorized: No token provided');
    }

    const blacklistedToken = await client.db("mytaxiutem").collection("blacklisted_tokens").findOne({ token });
    if (blacklistedToken) {
      console.error('Token is blacklisted');
      return res.status(403).send('You have Log Out! Please Log In To Access');
    }
    jwt.verify(token, secretKey, async (err, user) => {
      if (err) {
        return res.status(403).send('Forbidden: Invalid token');
      }
      if (user.role !== 'passenger') {
        return res.status(403).send('Forbidden: Only passengers can update their profile');
      }
      const allowedUpdates = [
        "name",
        "phone_number",
        "password",
        "emergency"
      ];
      const filteredUpdates = {};
      for (const key of allowedUpdates) {
        if (updateData[key] !== undefined) {
          filteredUpdates[key] = updateData[key];
        }
      }
      if (password) {
        filteredUpdates.password = bcrypt.hashSync(password, saltRounds);
      }
      const passenger = await client.db("mytaxiutem").collection("passenger").findOne(
        { username: { $eq: user.username } }
      );

      if (!passenger) {
        return res.status(404).send('Passenger not found');
      }
      await client.db("mytaxiutem").collection("passenger").updateOne(
        { username: { $eq: user.username } },
        { $set: filteredUpdates }
      );

      res.send('Information updated successfully!');
    });

  } catch (error) {
    console.error('Error updating passenger:', error);
    res.status(500).send('Internal Server Error');
  }
});

//---------------------------------------------------------------------------------------------------------------------------------------------

//make a rides
app.post('/bookarides', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      console.error('No token provided');
      return res.status(401).send('Unauthorized: No token provided');
    }

    const blacklistedToken = await client.db("mytaxiutem").collection("blacklisted_tokens").findOne({ token });
    if (blacklistedToken) {
      console.error('Token is blacklisted');
      return res.status(403).send('You have Log Out! Please Log In To Access');
    }

    jwt.verify(token, secretKey, async (err, user) => {
      if (err) {
        console.error('Token verification error:', err);
        return res.status(403).send('Forbidden: Invalid token');
      }
      if (user.role !== 'passenger') {
        console.error('Unauthorized role:', user.role);
        return res.status(403).send('Forbidden: Only passengers can book a ride');
      }

      console.log('Verified user:', user);

      const ride = await client.db("mytaxiutem").collection("rides").insertOne({
        "name" : user.name,
        "passengerId": user.username,
        "phone_number": user.phone_number,
        "pickuptime": req.body.pickuptime,
        "pickuplocation": req.body.pickuplocation,
        "dropofflocation": req.body.dropofflocation,
        "service_type": req.body.service_type,
        "payment_method": req.body.payment_method,
        "createdAt": new Date(),
        "status": "pending"
      });

      res.send('Ride has been booked successfully! Awaiting driver assignment.');
    });
  } catch (err) {
    console.error('Booking Error:', err);
    res.status(500).send('Something went wrong. Please try again later.');
  }
});

//See current ride
app.get('/currentbooking', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).send('Unauthorized: No token provided');
    }

    const blacklistedToken = await client.db("mytaxiutem").collection("blacklisted_tokens").findOne({ token });
    if (blacklistedToken) {
      console.error('Token is blacklisted');
      return res.status(403).send('You have Log Out! Please Log In To Access');
    }

    jwt.verify(token, secretKey, async (err, user) => {
      if (err) {
        console.error('Token verification error:', err);
        return res.status(403).send('Forbidden: Invalid token');
      }

      if (user.role !== 'admin' && user.role !== 'driver') {
        return res.status(403).send('Forbidden: You must be an admin or driver to access this resource');
      }

      const rides = await client.db("mytaxiutem").collection("rides").find().toArray();

      if (rides.length === 0) {
        res.send('No bookings at the moment.');
      } else {
        res.send(rides);  
      }
    });
  } catch (error) {
    console.error('Error fetching current booking:', error);
    res.status(500).send('Internal Server Error');
  }
});

//----------------------------------------------------------------------------------------------------------------------------------------------
//admin delete profile user or passenger
app.delete('/admin/delete', async (req, res) => {  
  try {
    const { username, userType } = req.body;
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).send('Unauthorized: No token provided');
    }

    const blacklistedToken = await client.db("mytaxiutem").collection("blacklisted_tokens").findOne({ token });
    if (blacklistedToken) {
      console.error('Token is blacklisted');
      return res.status(403).send('You have Log Out! Please Log In To Access');
    }

    jwt.verify(token, secretKey, async (err, user) => {
      if (err) {
        return res.status(403).send('Forbidden: Invalid token');
      }

      if (user.role !== 'admin') {
        return res.status(403).send('Forbidden: Only admins can delete users');
      }

      let targetUser;
      if (userType === 'passenger') {
        targetUser = await client.db("mytaxiutem").collection("passenger").findOne({ username: { $eq: username } });
        if (!targetUser) {
          return res.status(404).send('Passenger not found');
        }

        await client.db("mytaxiutem").collection("passenger").deleteOne({ username: { $eq: username } });
        res.send('Passenger successfully deleted');
      } else if (userType === 'driver') {
        targetUser = await client.db("mytaxiutem").collection("driver").findOne({ username: { $eq: username } });
        if (!targetUser) {
          return res.status(404).send('Driver not found');
        }

        await client.db("mytaxiutem").collection("driver").deleteOne({ username: { $eq: username } });
        res.send('Driver successfully deleted');
      } else {
        res.status(400).send('Invalid user type. Must be "passenger" or "driver".');
      }
    });

  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).send('Internal Server Error');
  }
});

// delete passenger
app.delete('/passenger/delete', async (req, res) => {  
  try {
    const { password, choice } = req.body;

    if (choice !== 'y' && choice !== 'n') {
      return res.status(400).send('Invalid choice. Please provide either "yes" or "no".');
    }

    if (choice === 'n') {
      return res.status(400).send('Deletion cancelled');
    }

    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).send('Unauthorized: No token provided');
    }

    const blacklistedToken = await client.db("mytaxiutem").collection("blacklisted_tokens").findOne({ token });
    if (blacklistedToken) {
      console.error('Token is blacklisted');
      return res.status(403).send('You have Log Out! Please Log In To Access');
    }

    jwt.verify(token, secretKey, async (err, user) => {
      if (err) {
        return res.status(403).send('Forbidden: Invalid token');
      }

      const passenger = await client.db("mytaxiutem").collection("passenger").findOne({ username: { $eq: user.username } });
      if (!passenger) {
        return res.status(404).send('Passenger not found');
      }

      const match = bcrypt.compareSync(password, passenger.password);
      if (!match) {
        return res.status(401).send('Incorrect password');
      }

      await client.db("mytaxiutem").collection("passenger").deleteOne({ username: { $eq: user.username } });

      res.send('Passenger successfully deleted');
    });
  } catch (error) {
    console.error('Error deleting passenger:', error);
    res.status(500).send('Internal Server Error');
  }
});

//delete driver
app.delete('/driver/delete', async (req, res) => {  
  try {
    const { password, choice } = req.body;

    if (choice !== 'y' && choice !== 'n') {
      return res.status(400).send('Invalid choice. Please provide either "y" or "n".');
    }

    if (choice === 'n') {
      return res.status(400).send('Deletion cancelled');
    }

    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).send('Unauthorized: No token provided');
    }

    const blacklistedToken = await client.db("mytaxiutem").collection("blacklisted_tokens").findOne({ token });
    if (blacklistedToken) {
      console.error('Token is blacklisted');
      return res.status(403).send('You have Log Out! Please Log In To Access');
    }

    jwt.verify(token, secretKey, async (err, user) => {
      if (err) {
        return res.status(403).send('Forbidden: Invalid token');
      }

      const driver = await client.db("mytaxiutem").collection("driver").findOne({ username: { $eq: user.username } });
      if (!driver) {
        return res.status(404).send('Driver not found');
      }

      const match = bcrypt.compareSync(password, driver.password);
      if (!match) {
        return res.status(401).send('Incorrect password');
      }

      await client.db("mytaxiutem").collection("driver").deleteOne({ username: { $eq: user.username } });

      res.send('Driver successfully deleted');
    });
  } catch (error) {
    console.error('Error deleting driver:', error);
    res.status(500).send('Internal Server Error');
  }
});

//----------------------------------------------------------------------------------------------------------------------------------------------

//admin view profile
app.get('/admin/userprofile', async (req, res) => {  
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      console.error('No token provided');
      return res.status(401).send('Unauthorized: No token provided');
    }

    const blacklistedToken = await client.db("mytaxiutem").collection("blacklisted_tokens").findOne({ token });
    if (blacklistedToken) {
      console.error('Token is blacklisted');
      return res.status(403).send('You have Log Out! Please Log In To Access');
    }

    jwt.verify(token, secretKey, async (err, user) => {
      if (err) {
        console.error('Token verification error:', err);
        return res.status(403).send('Forbidden: Invalid token');
      }

      if (user.role !== 'admin') {
        console.error('Unauthorized role:', user.role);
        return res.status(403).send('Forbidden: Admin role required');
      }

      const { userType } = req.body;

      if (userType === 'driver') {
        const driverProfiles = await client.db("mytaxiutem").collection("driver").find().toArray();
        res.send(driverProfiles); 
      } else if (userType === 'passenger') {
        const passengerProfiles = await client.db("mytaxiutem").collection("passenger").find().toArray();
        res.send(passengerProfiles);
      } else {
        res.status(400).send('Invalid userType. Please specify either "driver" or "passenger".');
      }
    });
  } catch (error) {
    console.error('Error fetching user profiles:', error);
    res.status(500).send('Internal Server Error');
  }
});

//passenger view driver
app.get('/passenger/driverprofile', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      console.error('No token provided');
      return res.status(401).send('Unauthorized: No token provided');
    }

    const blacklistedToken = await client.db("mytaxiutem").collection("blacklisted_tokens").findOne({ token });
    if (blacklistedToken) {
      console.error('Token is blacklisted');
      return res.status(403).send('You have Log Out! Please Log In To Access');
    }

    // Verify the token
    jwt.verify(token, secretKey, async (err, user) => {
      if (err) {
        console.error('Token verification error:', err); // Log the exact error
        return res.status(403).send('Forbidden: Invalid token');
      }

      // Check if the role is 'passenger'
      if (user.role !== 'passenger') {
        console.error('Unauthorized role:', user.role); // Log unauthorized role attempt
        return res.status(403).send('Forbidden: Only passengers can view driver profiles');
      }

      // If the role is passenger, fetch all drivers and return the limited profile data
      const drivers = await client.db("mytaxiutem").collection("driver").find().toArray();

      // Map the drivers to only include limited information
      const limitedDriverInfo = drivers.map(driver => ({
        name: driver.name,
        gender: driver.gender,
        phone_number: driver.phone_number,
        vehicle_type: driver.vehicle_type,
        vehicle_manufacturer: driver.vehicle_manufacturer
      }));

      // Send the limited driver information
      res.send(limitedDriverInfo);
    });
  } catch (error) {
    console.error('Error fetching driver profiles:', error);
    res.status(500).send('Internal Server Error');
  }
});

//acceptride
app.post('/driver/acceptride', async (req, res) => {
  try {
    const { choice } = req.body;

    if (choice !== 'y' && choice !== 'n') {
      return res.status(400).send('Invalid choice. Please provide either "y" or "n".');
    }

    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      console.error('No token provided');
      return res.status(401).send('Unauthorized: No token provided');
    }

    const blacklistedToken = await client.db("mytaxiutem").collection("blacklisted_tokens").findOne({ token });
    if (blacklistedToken) {
      console.error('Token is blacklisted');
      return res.status(403).send('You have Log Out! Please Log In To Access');
    }

    jwt.verify(token, secretKey, async (err, user) => {
      if (err) {
        console.error('Token verification error:', err);
        return res.status(403).send('Forbidden: Invalid token');
      }

      if (user.role !== 'driver') {
        console.error('Unauthorized role:', user.role);
        return res.status(403).send('Forbidden: Driver role required');
      }

      const pendingRides = await client.db("mytaxiutem").collection("rides").find({ status: "pending" })
        .sort({ createdAt: 1 })
        .toArray();

      if (pendingRides.length === 0) {
        return res.status(404).send('No pending rides available.');
      }

      const firstRide = pendingRides[0];

      if (choice === 'y') {
        await client.db("mytaxiutem").collection("ridehistory").insertOne({
          ...firstRide,
          acceptedBy: user.username,
          acceptedAt: new Date(),
          status: "accepted"
        });

        await client.db("mytaxiutem").collection("rides").deleteOne(
          { _id: firstRide._id }
        );

        res.send(`Ride with ID ${firstRide._id} accepted and moved to ride history!`);
      } 
      else if (choice === 'n') {
        await client.db("mytaxiutem").collection("rides").updateOne(
          { _id: firstRide._id },
          { $set: { 
              status: "pending", 
              rejectedBy: user.username 
            }
          }
        );

        res.send(`Ride with ID ${firstRide._id} rejected by you. Other drivers can now pick it.`);
      }
    });
  } catch (error) {
    console.error('Error processing the ride:', error);
    res.status(500).send('Internal Server Error');
  }
});


//-------------------------------------------------------------------------------------------------------------------------------------------

//ride history admin
app.get('/admin/history', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      console.error('No token provided');
      return res.status(401).send('Unauthorized: No token provided');
    }

    const blacklistedToken = await client.db("mytaxiutem").collection("blacklisted_tokens").findOne({ token });
    if (blacklistedToken) {
      console.error('Token is blacklisted');
      return res.status(403).send('You have Log Out! Please Log In To Access');
    }

    jwt.verify(token, secretKey, async (err, user) => {
      if (err) {
        console.error('Token verification error:', err);
        return res.status(403).send('Forbidden: Invalid token');
      }

      // Check if the role is 'admin'
      if (user.role !== 'admin') {
        console.error('Unauthorized role:', user.role);
        return res.status(403).send('Forbidden: Admin role required');
      }

      // Fetch the ride history
      const rideHistory = await client.db("mytaxiutem").collection("ridehistory").find().toArray();

      if (rideHistory.length === 0) {
        return res.send('No ride history available.');
      } else {
        return res.send(rideHistory);
      }
    });
  } catch (error) {
    console.error('Error fetching ride history:', error);
    res.status(500).send('Internal Server Error');
  }
});

//ride history driver
app.get('/driver/history', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      console.error('No token provided');
      return res.status(401).send('Unauthorized: No token provided');
    }

    const blacklistedToken = await client.db("mytaxiutem").collection("blacklisted_tokens").findOne({ token });
    if (blacklistedToken) {
      console.error('Token is blacklisted');
      return res.status(403).send('You have Log Out! Please Log In To Access');
    }

    jwt.verify(token, secretKey, async (err, user) => {
      if (err) {
        console.error('Token verification error:', err);
        return res.status(403).send('Forbidden: Invalid token');
      }

      if (user.role !== 'driver') {
        console.error('Unauthorized role:', user.role);
        return res.status(403).send('Forbidden: Driver role required');
      }

      const rideHistory = await client.db("mytaxiutem").collection("ridehistory").find(
        { acceptedBy: user.username } 
      ).toArray();

      if (rideHistory.length === 0) {
        res.send('No ride history available for this driver.');
      } else {
        res.send(rideHistory);
      }
    });
  } catch (error) {
    console.error('Error fetching ride history:', error);
    res.status(500).send('Internal Server Error');
  }
});

//logout
app.post('/logout', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).send('No token provided');
    }
    jwt.verify(token, secretKey, async (err, user) => {
      if (err) {
        return res.status(403).send('Forbidden: Invalid token');
      }

      await blacklistToken(token);
      res.status(200).send('Logged out successfully, token invalidated');
    });
  } catch (error) {
    console.error('Error logging out:', error);
    res.status(500).send('Internal Server Error');
  }
});


async function blacklistToken(token) {
  try {
    console.log("Blacklisting token:", token);
    await client.db("mytaxiutem").collection("blacklisted_tokens").insertOne({ token, createdAt: new Date() });
    console.log("Token blacklisted successfully.");
  } catch (error) {
    console.error('Error blacklisting token:', error);
  }
}

function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).send('Access Denied: No Token Provided');
  }

  jwt.verify(token, secretKey, (err, user) => {
    if (err) {
      return res.status(403).send('Invalid Token');
    }
    req.user = user;
    next();
  });
}

app.use(async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).send('No token provided');
  }

  const isBlacklisted = await checkBlacklist(token);
  if (isBlacklisted) {
    return res.status(403).send('Forbidden: Token is invalidated');
  }
  next();
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});

async function run() {
  try {
    await client.connect();
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
  }
}
run().catch(console.dir);