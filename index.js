const express = require('express')
const app = express()
const morgan = require('morgan')
const mongoose = require('mongoose')
const cors = require('cors')
require('dotenv/config')
const port = 4021 || process.env.PORT


app.use(cors());
app.options('*', cors())

app.use(express.json())
app.use(express.static("public"))


// const stripe = require("stripe")(process.env.STRIPE_PRIVATE_KEY)

// const storeItems = new Map([
//   [1, { priceInCents: 10000, name: "Learn React Today" }],
//   [2, { priceInCents: 20000, name: "Learn CSS Today" }],
// ])

// app.post("/create-checkout-session", async (req, res) => {
//     try {
//       const session = await stripe.checkout.sessions.create({
//         payment_method_types: ["card"],
//         mode: "payment",
//         line_items: req.body.items.map(item => {
//           const storeItem = storeItems.get(item.id)
//           return {
//             price_data: {
//               currency: "usd",
//               product_data: {
//                 name: storeItem.name,
//               },
//               unit_amount: storeItem.priceInCents,
//             },
//             quantity: item.quantity,
//           }
//         }),
//         success_url: `${process.env.CLIENT_URL}/success.html`,
//         cancel_url: `${process.env.CLIENT_URL}/cancel.html`,
//       })
//       res.json({ url: session.url })
//     } catch (e) {
//       res.status(500).json({ error: e.message })
//     }
//   })
  

const stripe = require("stripe")(process.env.STRIPE_PRIVATE_KEY)

app.post('/payments', async (req, res) => {
  const { amount } = req.body;

  try {
    const paymentIntent = await stripe.paymentIntents.create({
      amount,
      currency: 'usd',
    });

    res.status(200).send(paymentIntent.CLIENT_URL);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});




const productsRouter = require('./routes/products')
const categoriesRouter = require('./routes/categories')
const usersRouter = require('./routes/users')
const ordersRouter = require('./routes/orders')
const offersRouter = require('./routes/offers')



//middleware
app.use(express.json())
app.use(morgan('tiny'))
app.use('/public/uploads', express.static(__dirname + '/public/uploads'));
app.use(express.urlencoded({extended: false}))



//Routers
app.use('/api/products', productsRouter)
app.use('/api/categories', categoriesRouter)
app.use('/api/users', usersRouter)
app.use('/api/orders', ordersRouter)
app.use('/api/offers', offersRouter)




mongoose.connect(process.env.CONNECTION_STRING)
.then(()=>{
    console.log("Database connection is ready...")
})
.catch((err)=>{
    console.log(err.message)
})


app.listen(port,()=>{
    console.log("server running now")
})