const express = require('express');
const app = express();
const port = 3000;

app.get('/', (req,res) => {
    res.send('Testing the fourth project');
})

app.listen(port, () => {
    console.log(`Listening to port ${port} for the project number 4`);
})