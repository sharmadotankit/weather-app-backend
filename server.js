import express from 'express';
import bcrypt from 'bcrypt';
import cors from 'cors';
import bodyParser from 'body-parser';
import knex from 'knex';


const db = knex({
	client:'pg',
	connection:{
		host:'127.0.0.1',
		user:'postgres',
		password:'postgres',
		database:'weather-app'
	}
});


const app = express();
const saltRounds = 10;

app.use(bodyParser.json());
app.use(cors());
app.use(express.json());

app.get('/',(req,res)=>{
	res.send("<h1>HelloWorld</h1>");
});


app.post('/signin',(req,res)=>{
	const {email,password} = req.body;
	db.select('email','hash')
	.from('login')
	.where('email','=', email)
	.then(data=>
		{
			const isValid = bcrypt.compareSync(password, data[0].hash);
			if(isValid){
				return db.select('*')
				.from('users')
				.where('email','=',email)
				.then(user=>{
					res.json(user[0]);
				})
				.catch(err => res.status(400).json('Unable to get user'));
			}
			else{
				res.status(400).json('Wrong credentials');
			}
		}).catch(err => res.status(400).json('Wrong credentials'));
});

app.post('/register',(req,res)=>{
	const {name,email,password}=req.body;
	const passwordHash = bcrypt.hashSync(password, saltRounds, function(err, hash) {
		return hash;
	});

	db.transaction(trx=>{
		trx.insert({
			hash:passwordHash,
			email:email
		})
		.into('login')
		.returning('email')
		.then(loginEmail =>{
			return  trx('users')
					.returning('*')
					.insert({
						name:name,
						email:loginEmail[0].email,
					})
					.then(user=>{
						res.json(user[0]);
					})
					.then(trx.commit)
					.catch(trx.rollback)
		}).catch(err=> res.status(400).json('Unable to register'));
	}).catch(err=> res.status(400).json('Unable to register'));
});


app.put('/counter',(req,res)=>{

	let {id} = req.body;
	db('users').where('id','=',id)
	.increment('count',1)
	.returning('count')
	.then(count =>{
		res.json(count[0].count);
	}).catch(err => res.status(400).json('Unable to get the entries'))

})



app.listen(5000,()=>{ console.log("app is running in port 5000")});
