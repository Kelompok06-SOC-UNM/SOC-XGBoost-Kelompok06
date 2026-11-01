
import gradio as gr
import pandas as pd
import joblib

# Load model pipeline
pipeline = joblib.load('model_soc_xgboost_pipeline.joblib')

def predict_soc(connection_duration, port_entropy, bytes_ratio, packet_count):
    input_data = pd.DataFrame([[connection_duration, port_entropy, bytes_ratio, packet_count]],
                              columns=['connection_duration', 'port_entropy', 'bytes_ratio', 'packet_count'])
    
    pred = pipeline.predict(input_data)[0]
    prob = pipeline.predict_proba(input_data)[0]
    
    label = "REAL ATTACK (1)" if pred == 1 else "FALSE ALARM (0)"
    conf_dict = {"False Alarm (0)": float(prob[0]), "Real Attack (1)": float(prob[1])}
    
    recommendation = "TINDAKAN: Isolasi host & investigasi insiden segera!" if pred == 1 else "TINDAKAN: Abaikan log sebagai false positive / normal traffic."
    
    return label, conf_dict, recommendation

demo = gr.Interface(
    fn=predict_soc,
    inputs=[
        gr.Number(label="Durasi Koneksi / connection_duration (detik)", value=12.0),
        gr.Number(label="Indeks Entropi Port / port_entropy (0 - 8)", value=1.85),
        gr.Number(label="Rasio Bytes Keluar/Masuk / bytes_ratio", value=0.95),
        gr.Number(label="Jumlah Paket Data / packet_count (Packets)", value=120)
    ],
    outputs=[
        gr.Textbox(label="Kesimpulan Model (Label Prediksi)"),
        gr.Label(label="Confidence Score / Probabilitas Kelas"),
        gr.Textbox(label="Rekomendasi Operasional SOC")
    ],
    title="PT Teknologi Keamanan Siber - SOC Alert Threat Intelligence Portal",
    description="Masukkan parameter log jaringan untuk mendeteksi validitas ancaman SOC secara real-time."
)

if __name__ == "__main__":
    demo.launch(share=True)
