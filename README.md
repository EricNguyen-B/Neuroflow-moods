# Neuroflow-moods

## Installation Instructions
<code>pip install flask</code>
<br>
```pip install flask-restful```
<br>
``` pip install requests```
<br>
```pip install sql-alchemy```
<br>
```pip install -U Werkzeug```
<br>
```pip install flask-login```

## Application Instructions
<p>Recommended Testing Resources: Postman</p>
<ol>
  <li>Create a user with the post method on /user endpoint</li>
  <li>Get all of the users with the get method on /user endpoint</li>
  <li>Promote a user to admin ability with the put method on /user/public_id </li>
  <li>Login the admin user with basic authorization</li>
  <li>Submit mood values as the the current user with the get method on /mood endpoint</li>
  <li>Get all of the mood values of the current user with the get method on /mood endpoint</li>
  </ol>

## Production Scenario
If this were a production application, I would need to utilize technologies that could handle user scalability. The technologies I chose for this assessment uses sqlite as the database and flask as a lightweight backend framework. If the production application were to handle more users, then we would need to implement a database that works well with large datasets like PostgreSQL. We could also use a different python-based framework such as Django because it is designed to accomodate heavy traffice demands and offers flexible customization features such as content management making it versatile for user feature needs. 
