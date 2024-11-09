import asab
import asab.web
import bcrypt
from aiohttp import web
from auth import register_user, login_user, verify_token
from database import get_db_connection

class MyApplication(asab.Application):

    def __init__(self):
        super().__init__()
        self.add_module(asab.web.Module)

        websvc = self.get_service("asab.WebService")

        container = asab.web.WebContainer(websvc, 'my:web', config={"listen": "0.0.0.0:8080"})

        container.WebApp.router.add_post('/auth/register', self.handle_register)
        container.WebApp.router.add_post('/auth/login', self.handle_login)
        container.WebApp.router.add_get('/users', self.handle_get_users)
        container.WebApp.router.add_post('/users', self.handle_post_user)
        container.WebApp.router.add_get('/users/{id}', self.handle_get_user)
        container.WebApp.router.add_put('/users/{id}', self.handle_update_user)
        container.WebApp.router.add_delete('/users/{id}', self.handle_delete_user)

    async def handle_register(self, request):
        print("Register endpoint hit!") 
        try:
            data = await request.json()
            print("Received data:", data)  
            register_user(data['username'], data['password'])
            return web.json_response({"message": "User registered successfully"})
        except Exception as e:
            print(f"Error in handle_register: {e}") 
            return web.json_response({"error": str(e)}, status=500)
   
    async def handle_login(self, request):
        try:
            data = await request.json()
            user_id, token= login_user(data['username'], data['password'])
            return web.json_response({"user_id": user_id, "token": token})
        except Exception as e:
            return web.json_response({"error": str(e)}, status=400)
        
    async def handle_get_users(self, request):
        token = request.headers.get("Authorization")
        verify_token(token) 

        conn = get_db_connection()
        users = conn.execute("SELECT id, username FROM users").fetchall()
        conn.close()
        users_list = [dict(user) for user in users]
        return web.json_response(users_list)
    
    async def handle_post_user(self, request):
        token = request.headers.get("Authorization")
        verify_token(token)
        
        data = await request.json()
        username = data.get("username")
        password = data.get("password")
        if not username and password:
            return web.json_response({"error": "Username and password is required"}, status=400)

        conn = get_db_connection()
        try:
            conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)
        finally:
            conn.close()
        return web.json_response({"message": "User created successfully"}, status=201)
      
    async def handle_get_user(self, request):
        token = request.headers.get("Authorization")
        verify_token(token) 
        user_id = int(request.match_info['id'])
        conn = get_db_connection()
        user = conn.execute("SELECT id, username FROM users WHERE id = ?", (user_id,)).fetchone()
        conn.close()
        if user:
            return web.json_response(dict(user))
        else:
            return web.json_response({"error": "User not found"}, status=404)

    async def handle_update_user(self, request):
        token = request.headers.get("Authorization")
        verify_token(token)  
        user_id = int(request.match_info['id'])
        data = await request.json()
        conn = get_db_connection()
        conn.execute("UPDATE users SET username = ?, password = ? WHERE id = ?", 
                     (data['username'], bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt()), user_id))
        conn.commit()
        conn.close()
        return web.json_response({"message": "User updated successfully"})

    async def handle_delete_user(self, request):
        token = request.headers.get("Authorization")
        verify_token(token)  
        user_id = int(request.match_info['id'])
        conn = get_db_connection()
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
        return web.json_response({"message": "User deleted successfully"})

    async def handle_get_users(self, request):
        try:
            token = request.headers.get("Authorization")
            verify_token(token)
            conn = get_db_connection()
            users = conn.execute("SELECT id, username FROM users").fetchall()
            conn.close()
            return web.json_response([dict(user) for user in users])
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)

if __name__ == '__main__':
    app = MyApplication()
    app.run()
