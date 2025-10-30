
# Serve main application
@app.route('/')
def index():
    return render_template('index.html')

# Quiz routes (keep your existing routes)
@app.route('/eng_quiz')
def eng_quiz():
    return render_template('eng_quiz.html')
    
@app.route('/med_quiz')
def med_quiz():
    return render_template('med_quiz.html')
    
@app.route('/law_quiz')
def law_quiz():
    return render_template('law_quiz.html')
    
@app.route('/def_quiz')
def def_quiz():
    return render_template('def_quiz.html')
    
@app.route('/agr_quiz')
def agr_quiz():
    return render_template('agr_quiz.html')
    
@app.route('/spo_quiz')
def spo_quiz():
    return render_template('spo_quiz.html')
    
@app.route('/ent_quiz')
def ent_quiz():
    return render_template('ent_quiz.html')
    
@app.route('/aca_quiz')
def aca_quiz():
    return render_template('aca_quiz.html')
    
# Serve guidance pages (keep your existing routes)
@app.route('/law1')
def law_guidance1():
    return render_template('law1.html')
    
@app.route('/law2')
def law_guidance2():
    return render_template('law2.html')
    
@app.route('/eng1')
def eng_guidance1():
    return render_template('eng1.html')
    
@app.route('/eng2')
def eng_guidance2():
    return render_template('eng2.html')
    
@app.route('/med1')
def med_guidance1():
    return render_template('med1.html')
    
@app.route('/med2')
def med_guidance2():
    return render_template('med2.html')
    
@app.route('/def1')
def def_guidance1():
    return render_template('def1.html')
    
@app.route('/def2')
def def_guidance2():
    return render_template('def2.html')
    
@app.route('/agr1')
def agr_guidance1():
    return render_template('agr1.html')
    
@app.route('/agr2')
def agr_guidance2():
    return render_template('agr2.html')
    
@app.route('/spo1')
def spo_guidance1():
    return render_template('spo1.html')
    
@app.route('/spo2')
def spo_guidance2():
    return render_template('spo2.html')
    
@app.route('/ent1')
def ent_guidance1():
    return render_template('ent1.html')
    
@app.route('/ent2')
def ent_guidance2():
    return render_template('ent2.html')
    
@app.route('/aca1')
def aca_guidance1():
    return render_template('aca1.html')
    
@app.route('/aca2')
def aca_guidance2():
    return render_template('aca2.html')