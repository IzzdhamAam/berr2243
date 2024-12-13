const express = require('express')
const app = express()
const port = process.env.PORT || 3000;

const { MongoClient, ServerApiVersion } = require('mongodb');
const uri = "mongodb+srv://b122310299:Kickflip.09@cluster0.mxtvq.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";
// Create a MongoClient with a MongoClientOptions object to set the Stable API version

const bcrypt = require('bcrypt');
const saltRounds = 10;
//hashing

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

app.use(express.json())

app.get('/', (req, res) => {
   res.send('Capiq Hesmes')
})

app.get('/:username/:password', (req, res) => {  //req.params (using parameters) (can put >1 parameters)
   console.log(req.params)
   res.send('Hello Aam' + req.params.username + req.params.password) //return back username (username bawah == username atas)
})

//body (login)
app.get('/login', async (req, res) => {  
  const user = await client.db("sample_mflix").collection("user2").findOne(
    { username:{ $eq:req.body.username }}
 )

if (!user){
  res.send('username not exist')
  return
}

console.log(req.body.password)
console.log(user.password)

const match = bcrypt.compareSync(req.body.password, user.password);

if (match){
  res.send('login success')
  } else  {
    res.send('login failed')
  }
})


//body (register)
app.post('/register', async (req, res) => {  
  const user = await client.db("sample_mflix").collection("user2").findOne (
   {username: {$eq: req.body.username}}
  )

  if (user){
   res.send('username exist')
   return
  }

   const hash = bcrypt.hashSync(req.body.password, saltRounds);
   
   client.db("sample_mflix").collection("user2").insertOne({
      "name" : req.body.name,
      "username" : req.body.username,
      "password" : hash
   })
   res.send(' Register successfully ' + req.body.username + req.body.password)
})

app.listen(port, () => {
   console.log(`Example app listening on port ${port}`)
})

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();
    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    //await client.close();
  }
}
run().catch(console.dir);