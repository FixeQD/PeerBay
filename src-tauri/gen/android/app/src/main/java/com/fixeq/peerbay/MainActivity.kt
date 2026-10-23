package com.fixeq.peerbay

import android.os.Bundle
import androidx.activity.enableEdgeToEdge

class MainActivity : TauriActivity() {
  private val nativeBridge = PeerBayNativeBridge()

  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    nativeBridge.onCreated()
    super.onCreate(savedInstanceState)
  }

  override fun onResume() {
    super.onResume()
    nativeBridge.onResumed()
  }

  override fun onPause() {
    nativeBridge.onPaused()
    super.onPause()
  }

  override fun onDestroy() {
    nativeBridge.onDestroyed()
    super.onDestroy()
  }
}
