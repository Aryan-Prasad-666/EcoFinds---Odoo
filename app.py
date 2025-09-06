from flask import Flask, render_template, request, redirect, url_for, flash, session
from supabase import create_client, Client
from werkzeug.utils import secure_filename
import os
from dotenv import load_dotenv
from decimal import Decimal

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
load_dotenv()
supabase_url = os.getenv('SUPABASE_URL')
supabase_key = os.getenv('SUPABASE_KEY')
supabase: Client = create_client(supabase_url, supabase_key)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg'}

@app.context_processor
def inject_supabase_and_user():
    current_user = None
    if 'user_id' in session:
        try:
            if 'access_token' in session and 'refresh_token' in session:
                supabase.auth.set_session(session['access_token'], session['refresh_token'])
            user_data = supabase.table('profiles').select('username, email, image').eq('id', session['user_id']).single().execute().data
            current_user = {
                'id': session['user_id'],
                'username': user_data['username'],
                'email': user_data['email'],
                'image': user_data['image'],
                'is_authenticated': True
            }
        except Exception as e:
            print(f"Error fetching user data: {str(e)}")
            session.pop('user_id', None)
            session.pop('access_token', None)
            session.pop('refresh_token', None)
    return dict(supabase=supabase, current_user=current_user)

@app.route('/products/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    categories = ['Electronics', 'Clothing', 'Furniture', 'Books', 'Other']
    if request.method == 'POST':
        files = request.files.getlist('images')
        valid_files = [f for f in files if f and allowed_file(f.filename)]
        
        if len(valid_files) < 1:
            flash('At least one image is required (PNG, JPG, or JPEG).')
            return redirect(url_for('new_product'))
        if len(valid_files) > 10:
            flash('Maximum 10 images allowed.')
            return redirect(url_for('new_product'))
        
        try:
            if 'access_token' not in session or 'refresh_token' not in session:
                flash('Session expired. Please log in again.')
                return redirect(url_for('login'))
            
            try:
                supabase.auth.set_session(session['access_token'], session['refresh_token'])
                current_session = supabase.auth.get_session()
                if not current_session.user:
                    print("Session invalid, attempting to refresh...")
                    supabase.auth.refresh_session()
                    session['access_token'] = supabase.auth.get_session().access_token
                    session['refresh_token'] = supabase.auth.get_session().refresh_token
                    current_session = supabase.auth.get_session()
            except Exception as e:
                print(f"Token refresh failed: {str(e)}")
                flash('Session expired. Please log in again.')
                return redirect(url_for('login'))
            
            current_user_id = current_session.user.id if current_session.user else None
            auth_user_id = supabase.auth.get_user().user.id if supabase.auth.get_user().user else None
            print(f"Current session user ID: {current_user_id}")
            print(f"Supabase auth user ID: {auth_user_id}")
            print(f"Session user_id: {session['user_id']}")
            print(f"Access token: {session.get('access_token')[:10]}...")
            
            if not request.form['title'].strip():
                flash('Title is required.')
                return redirect(url_for('new_product'))
            if request.form['category'] not in categories:
                flash('Invalid category.')
                return redirect(url_for('new_product'))
            try:
                price = Decimal(str(request.form['price']))
                if price <= 0:
                    flash('Price must be greater than 0.')
                    return redirect(url_for('new_product'))
            except ValueError:
                flash('Invalid price format.')
                return redirect(url_for('new_product'))
            
            product_data = {
                'title': request.form['title'],
                'description': request.form['description'],
                'category': request.form['category'],
                'price': str(price), 
                'user_id': str(session['user_id'])
            }
            print(f"Inserting product data: {product_data}")
            product_response = supabase.table('products').insert(product_data).execute()
            print(f"Product insert response: {product_response}")
            product_id = product_response.data[0]['id']
            
            for file in valid_files:
                filename = secure_filename(file.filename)
                file_content = file.read()
                try:
                    print(f"Uploading image: {product_id}/{filename}")
                    storage_response = supabase.storage.from_('product-images').upload(f'{product_id}/{filename}', file_content)
                    print(f"Storage upload response: {storage_response}")
                    image_data = {
                        'product_id': product_id,
                        'image_path': f'{product_id}/{filename}'
                    }
                    print(f"Inserting image data: {image_data}")
                    image_response = supabase.table('product_images').insert(image_data).execute()
                    print(f"Image insert response: {image_response}")
                except Exception as img_error:
                    print(f"Error uploading or inserting image {filename}: {str(img_error)}")
                    raise img_error
            
            flash('Product listed successfully')
            return redirect(url_for('dashboard'))
        except Exception as e:
            print(f"Error in new_product: {str(e)}")
            flash(f'Error listing product: {str(e)}')
            return redirect(url_for('new_product'))
    
    return render_template('new_product.html', categories=categories)

@app.route('/products/<int:id>/edit', methods=['GET', 'POST'])
def edit_product(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        if 'access_token' in session and 'refresh_token' in session:
            supabase.auth.set_session(session['access_token'], session['refresh_token'])
        product = supabase.table('products').select('*, product_images(image_path)').eq('id', id).single().execute().data
        if not product or product['user_id'] != session['user_id']:
            flash('Unauthorized')
            return redirect(url_for('dashboard'))
    except Exception as e:
        flash(f'Error loading product: {str(e)}')
        return redirect(url_for('dashboard'))
    
    categories = ['Electronics', 'Clothing', 'Furniture', 'Books', 'Other']
    if request.method == 'POST':
        try:
            if not request.form['title'].strip():
                flash('Title is required.')
                return redirect(url_for('edit_product', id=id))
            if request.form['category'] not in categories:
                flash('Invalid category.')
                return redirect(url_for('edit_product', id=id))
            try:
                price = Decimal(str(request.form['price']))
                if price <= 0:
                    flash('Price must be greater than 0.')
                    return redirect(url_for('edit_product', id=id))
            except ValueError:
                flash('Invalid price format.')
                return redirect(url_for('edit_product', id=id))
            
            supabase.table('products').update({
                'title': request.form['title'],
                'description': request.form['description'],
                'category': request.form['category'],
                'price': str(price)  
            }).eq('id', id).execute()
            
            delete_images = request.form.getlist('delete_images')
            for image_path in delete_images:
                supabase.storage.from_('product-images').remove([image_path])
                supabase.table('product_images').delete().eq('image_path', image_path).execute()
            
            files = request.files.getlist('images')
            valid_files = [f for f in files if f and allowed_file(f.filename)]
            current_image_count = len(product['product_images']) - len(delete_images)
            
            if current_image_count + len(valid_files) < 1:
                flash('At least one image is required.')
                return redirect(url_for('edit_product', id=id))
            if current_image_count + len(valid_files) > 10:
                flash('Maximum 10 images allowed.')
                return redirect(url_for('edit_product', id=id))
            
            for file in valid_files:
                filename = secure_filename(file.filename)
                file_content = file.read()
                supabase.storage.from_('product-images').upload(f'{id}/{filename}', file_content)
                supabase.table('product_images').insert({
                    'product_id': id,
                    'image_path': f'{id}/{filename}'
                }).execute()
            
            flash('Product updated successfully')
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash(f'Error updating product: {str(e)}')
            return redirect(url_for('edit_product', id=id))
    
    return render_template('edit_product.html', product=product, categories=categories)

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        username = request.form['username']
        
        try:
            response = supabase.auth.sign_up({
                'email': email,
                'password': password
            })
            user = response.user
            sign_in_response = supabase.auth.sign_in_with_password({
                'email': email,
                'password': password
            })
            supabase.table('profiles').insert({
                'id': user.id,
                'username': username,
                'email': email,
                'image': 'user_image.jpg'
            }).execute()
            session['user_id'] = user.id
            session['access_token'] = sign_in_response.session.access_token
            session['refresh_token'] = sign_in_response.session.refresh_token
            print(f"Register successful, user_id: {user.id}, access_token: {sign_in_response.session.access_token[:10]}...")
            flash('Registration successful!')
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash(f'Registration failed: {str(e)}')
            return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        try:
            response = supabase.auth.sign_in_with_password({
                'email': email,
                'password': password
            })
            user = response.user
            session['user_id'] = user.id
            session['access_token'] = response.session.access_token
            session['refresh_token'] = response.session.refresh_token
            print(f"Login successful, user_id: {user.id}, access_token: {response.session.access_token[:10]}...")
            flash('Login successful!')
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash(f'Invalid email or password: {str(e)}')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    supabase.auth.sign_out()
    session.pop('user_id', None)
    session.pop('access_token', None)
    session.pop('refresh_token', None)
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        if 'access_token' in session and 'refresh_token' in session:
            supabase.auth.set_session(session['access_token'], session['refresh_token'])
        user_data = supabase.table('profiles').select('*').eq('id', session['user_id']).single().execute().data
        products = supabase.table('products').select('*, product_images(image_path)').eq('user_id', session['user_id']).execute().data
        return render_template('dashboard.html', user=user_data, products=products)
    except Exception as e:
        flash(f'Error loading dashboard: {str(e)}')
        return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        if 'access_token' in session and 'refresh_token' in session:
            supabase.auth.set_session(session['access_token'], session['refresh_token'])
        user_data = supabase.table('profiles').select('*').eq('id', session['user_id']).single().execute().data
    except Exception as e:
        flash(f'Error loading profile: {str(e)}')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        update_data = {'username': username, 'email': email}
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_content = file.read()
                supabase.storage.from_('user-images').upload(f'{session["user_id"]}/{filename}', file_content)
                update_data['image'] = f'{session["user_id"]}/{filename}'
            elif file.filename:
                flash('Invalid file type. Please upload PNG, JPG, or JPEG.')
        
        if new_password or confirm_password:
            if new_password != confirm_password:
                flash('Passwords do not match.')
                return redirect(url_for('profile'))
            if len(new_password) < 6:
                flash('Password must be at least 6 characters.')
                return redirect(url_for('profile'))
            try:
                supabase.auth.set_session(session['access_token'], session['refresh_token'])
                supabase.auth.update_user({'password': new_password})
                flash('Password updated successfully.')
                sign_in_response = supabase.auth.sign_in_with_password({
                    'email': email,
                    'password': new_password
                })
                session['access_token'] = sign_in_response.session.access_token
                session['refresh_token'] = sign_in_response.session.refresh_token
            except Exception as e:
                flash(f'Password update failed: {str(e)}')
                return redirect(url_for('profile'))
        
        try:
            supabase.table('profiles').update(update_data).eq('id', session['user_id']).execute()
            flash('Profile updated successfully.')
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash(f'Profile update failed: {str(e)}')
        
    return render_template('profile.html', user=user_data)

@app.route('/products/<int:id>/delete', methods=['POST'])
def delete_product(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        if 'access_token' in session and 'refresh_token' in session:
            supabase.auth.set_session(session['access_token'], session['refresh_token'])
        product = supabase.table('products').select('*, product_images(image_path)').eq('id', id).single().execute().data
        if not product or product['user_id'] != session['user_id']:
            flash('Unauthorized')
            return redirect(url_for('dashboard'))
        
        for image in product['product_images']:
            supabase.storage.from_('product-images').remove([image['image_path']])
        
        supabase.table('products').delete().eq('id', id).execute()
        flash('Product deleted successfully')
        return redirect(url_for('dashboard'))
    except Exception as e:
        flash(f'Error deleting product: {str(e)}')
        return redirect(url_for('dashboard'))

@app.route('/products')
def browse_products():
    category = request.args.get('category')
    search = request.args.get('search')
    
    try:
        if 'access_token' in session and 'refresh_token' in session:
            supabase.auth.set_session(session['access_token'], session['refresh_token'])
            current_user_id = supabase.auth.get_session().user.id if supabase.auth.get_session().user else None
            print(f"Current user ID: {current_user_id}")
        else:
            print("No authenticated user (public access)")
        
        query = supabase.table('products').select('*, product_images(image_path)')
        if category:
            query = query.eq('category', category)
        if search:
            query = query.ilike('title', f'%{search}%')
        
        products = query.execute().data
        print(f"Fetched products: {products}")
        categories = ['Electronics', 'Clothing', 'Furniture', 'Books', 'Other']
        return render_template('browse_products.html', products=products, categories=categories)
    except Exception as e:
        print(f"Error in browse_products: {str(e)}")
        flash(f'Error loading products: {str(e)}')
        return redirect(url_for('index'))

@app.route('/products/<int:id>')
def product_detail(id):
    try:
        if 'access_token' in session and 'refresh_token' in session:
            supabase.auth.set_session(session['access_token'], session['refresh_token'])
        product = supabase.table('products').select('*, product_images(image_path)').eq('id', id).single().execute().data
        if not product:
            flash('Product not found')
            return redirect(url_for('browse_products'))
        return render_template('product_detail.html', product=product)
    except Exception as e:
        flash(f'Error loading product: {str(e)}')
        return redirect(url_for('browse_products'))

@app.route('/purchases')
def purchases():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        if 'access_token' in session and 'refresh_token' in session:
            supabase.auth.set_session(session['access_token'], session['refresh_token'])
        purchases = supabase.table('purchases').select('*, product:products(*, product_images(image_path))').eq('user_id', session['user_id']).execute().data
        return render_template('purchases.html', purchases=purchases)
    except Exception as e:
        flash(f'Error loading purchases: {str(e)}')
        return redirect(url_for('login'))

@app.route('/cart')
def cart():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        if 'access_token' in session and 'refresh_token' in session:
            supabase.auth.set_session(session['access_token'], session['refresh_token'])
            print(f"Cart: Current user ID: {supabase.auth.get_session().user.id}")
        cart_items = supabase.table('cart').select('*, product:products(*, product_images(image_path))').eq('user_id', session['user_id']).execute().data
        print(f"Fetched cart items: {cart_items}")
        return render_template('cart.html', cart_items=cart_items)
    except Exception as e:
        print(f"Error in cart: {str(e)}")
        flash(f'Error loading cart: {str(e)}')
        return redirect(url_for('login'))

@app.route('/cart/add/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        if 'access_token' in session and 'refresh_token' in session:
            supabase.auth.set_session(session['access_token'], session['refresh_token'])
            print(f"Add to cart: Current user ID: {supabase.auth.get_session().user.id}")
        
        product = supabase.table('products').select('id').eq('id', product_id).single().execute().data
        if not product:
            flash('Product not found')
            return redirect(url_for('browse_products'))
        
        cart_data = {
            'user_id': str(session['user_id']),
            'product_id': product_id
        }
        print(f"Inserting cart data: {cart_data}")
        supabase.table('cart').insert(cart_data).execute()
        flash('Product added to cart')
        return redirect(url_for('browse_products'))
    except Exception as e:
        print(f"Error adding to cart: {str(e)}")
        flash(f'Error adding to cart: {str(e)}')
        return redirect(url_for('browse_products'))

@app.route('/cart/remove/<int:id>', methods=['POST'])
def remove_from_cart(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        if 'access_token' in session and 'refresh_token' in session:
            supabase.auth.set_session(session['access_token'], session['refresh_token'])
        cart_item = supabase.table('cart').select('*').eq('id', id).single().execute().data
        if not cart_item or cart_item['user_id'] != session['user_id']:
            flash('Unauthorized')
            return redirect(url_for('cart'))
        
        supabase.table('cart').delete().eq('id', id).execute()
        flash('Product removed from cart')
        return redirect(url_for('cart'))
    except Exception as e:
        print(f"Error removing from cart: {str(e)}")
        flash(f'Error removing from cart: {str(e)}')
        return redirect(url_for('cart'))

@app.route('/purchase/<int:product_id>', methods=['POST'])
def purchase_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        if 'access_token' in session and 'refresh_token' in session:
            supabase.auth.set_session(session['access_token'], session['refresh_token'])
        supabase.table('purchases').insert({
            'user_id': str(session['user_id']),
            'product_id': product_id
        }).execute()
        flash('Product purchased successfully')
        return redirect(url_for('purchases'))
    except Exception as e:
        print(f"Error purchasing product: {str(e)}")
        flash(f'Error purchasing product: {str(e)}')
        return redirect(url_for('purchases'))

if __name__ == '__main__':
    app.run(debug=True)